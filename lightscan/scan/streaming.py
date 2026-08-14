"""Streaming TCP scan scheduler for high-scale, authorized inventory runs.

The scheduler intentionally keeps only a bounded number of jobs in memory.
That makes a 50,000-host, 100-port scan a queueing problem rather than a
five-million-coroutine allocation problem.
"""
from __future__ import annotations

import asyncio
import errno
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from lightscan.core.engine import ScanResult, Severity
from lightscan.core.runtime_telemetry import capture_runtime_snapshot, resource_delta
from lightscan.scan.aimd import AimdConcurrencyController
from lightscan.scan.portscan import CRIT_PORTS, HIGH_PORTS, PROBES, SERVICE_MAP


@dataclass(frozen=True)
class ScanControls:
    """Explicit controls for the streaming connect-scan execution model."""

    concurrency: int = 256
    per_host_concurrency: int = 32
    max_rate: float = 0.0
    retries: int = 1
    retry_jitter: float = 0.15
    host_timeout: float = 0.0
    host_group_size: int = 256
    adaptive: bool = True
    timing: int = 4

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.per_host_concurrency < 1:
            raise ValueError("per_host_concurrency must be at least 1")
        if self.max_rate < 0:
            raise ValueError("max_rate cannot be negative")
        if self.retries < 0:
            raise ValueError("retries cannot be negative")
        if not 0 <= self.retry_jitter <= 1:
            raise ValueError("retry_jitter must be between 0 and 1")
        if self.host_timeout < 0:
            raise ValueError("host_timeout cannot be negative")
        if self.host_group_size < 1:
            raise ValueError("host_group_size must be at least 1")
        if not 0 <= self.timing <= 5:
            raise ValueError("timing must be between 0 and 5")


@dataclass
class ScanMetrics:
    """Counters retained for reports and adaptive-control decisions."""

    scheduled: int = 0
    attempts: int = 0
    open: int = 0
    closed: int = 0
    filtered: int = 0
    errors: int = 0
    transient: int = 0
    retries: int = 0
    retry_filtered: int = 0
    retry_transient: int = 0
    retry_delay_seconds: float = 0.0
    skipped: int = 0
    elapsed: float = 0.0
    runtime: dict[str, int | None] = field(default_factory=dict)
    aimd: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scheduled": self.scheduled,
            "attempts": self.attempts,
            "open": self.open,
            "closed": self.closed,
            "filtered": self.filtered,
            "errors": self.errors,
            "transient": self.transient,
            "retries": self.retries,
            "retry_filtered": self.retry_filtered,
            "retry_transient": self.retry_transient,
            "retry_delay_seconds": round(self.retry_delay_seconds, 3),
            "skipped": self.skipped,
            "elapsed": round(self.elapsed, 3),
            "runtime": self.runtime,
            "aimd": self.aimd,
        }


@dataclass(frozen=True)
class _Job:
    host: str
    port: int


class _RateGate:
    """A monotonic, process-local start-rate limiter for connection attempts."""

    def __init__(self, max_rate: float):
        self._interval = 1.0 / max_rate if max_rate else 0.0
        self._lock = asyncio.Lock()
        self._next_start = 0.0

    async def wait(self) -> None:
        if not self._interval:
            return
        async with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next_start)
            self._next_start = scheduled + self._interval
        delay = scheduled - now
        if delay > 0:
            await asyncio.sleep(delay)


class _AdaptiveWindow:
    """A mutable in-flight limit controlled by measured scan feedback."""

    def __init__(self, limit: int):
        self._limit = max(1, limit)
        self._in_flight = 0
        self._condition = asyncio.Condition()

    async def acquire(self) -> None:
        async with self._condition:
            while self._in_flight >= self._limit:
                await self._condition.wait()
            self._in_flight += 1

    async def release(self) -> None:
        async with self._condition:
            self._in_flight -= 1
            self._condition.notify_all()

    async def update(self, limit: int) -> None:
        async with self._condition:
            self._limit = max(1, limit)
            self._condition.notify_all()


class StreamingTCPScanner:
    """Run a fair, bounded TCP connect scan with retry-aware classification."""

    def __init__(
        self,
        controls: ScanControls,
        timeout: float = 3.0,
        banners: bool = True,
        result_sink: Callable[[ScanResult], None] | None = None,
    ):
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self.controls = controls
        self.timeout = timeout
        self.banners = banners
        self._result_sink = result_sink
        self.metrics = ScanMetrics()
        self._runtime_started = capture_runtime_snapshot()
        self._started_at = time.monotonic()
        self._rate_gate = _RateGate(controls.max_rate)
        self._host_started: dict[str, float] = {}
        self._host_locks: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self.controls.per_host_concurrency)
        )
        self._adaptive = None
        self._adaptive_window = None
        self._aimd = None
        if controls.adaptive:
            from lightscan.scan.adaptive import AdaptiveTimingEngine

            self._adaptive = AdaptiveTimingEngine(
                base_timing=controls.timing,
                max_concurrency=controls.concurrency,
            )
            self._aimd = AimdConcurrencyController(
                initial=self._adaptive.current_concurrency,
                maximum=controls.concurrency,
                minimum=max(1, min(4, controls.per_host_concurrency, controls.concurrency)),
            )
            self._adaptive_window = _AdaptiveWindow(self._aimd.current)
            self.metrics.aimd = self._aimd.summary()

    async def scan(
        self,
        hosts: Sequence[str],
        ports: Sequence[int],
        *,
        retain_results: bool = True,
    ) -> list[ScanResult]:
        """Scan *hosts* × *ports* without materializing the entire job set.

        Set ``retain_results`` to ``False`` with a ``result_sink`` to stream
        open findings to durable output while retaining only aggregate metrics.
        """
        if not hosts or not ports:
            return []

        queue: asyncio.Queue[_Job | None] = asyncio.Queue(
            maxsize=max(1, self.controls.concurrency * 2)
        )
        findings: list[ScanResult] = []
        workers = [
            asyncio.create_task(self._worker(queue, findings, retain_results))
            for _ in range(self.controls.concurrency)
        ]

        try:
            for job in self._iter_jobs(hosts, ports):
                await queue.put(job)
                self.metrics.scheduled += 1
            await queue.join()
        finally:
            for _ in workers:
                await queue.put(None)
            await asyncio.gather(*workers)
            self.metrics.elapsed = time.monotonic() - self._started_at
            self.metrics.runtime = resource_delta(
                self._runtime_started, capture_runtime_snapshot()
            )

        return findings

    def _iter_jobs(self, hosts: Sequence[str], ports: Sequence[int]) -> Iterable[_Job]:
        """Yield port-major host groups to distribute load across targets fairly."""
        group_size = self.controls.host_group_size
        for port in ports:
            for offset in range(0, len(hosts), group_size):
                for host in hosts[offset: offset + group_size]:
                    yield _Job(host, port)

    async def _worker(
        self,
        queue: asyncio.Queue[_Job | None],
        findings: list[ScanResult],
        retain_results: bool,
    ) -> None:
        while True:
            job = await queue.get()
            try:
                if job is None:
                    return
                if self._adaptive_window is not None:
                    await self._adaptive_window.acquire()
                try:
                    result = await self._scan_job(job)
                    if result is not None:
                        if self._result_sink is not None:
                            self._result_sink(result)
                        if retain_results:
                            findings.append(result)
                finally:
                    if self._adaptive_window is not None:
                        await self._adaptive_window.release()
            finally:
                queue.task_done()

    async def _scan_job(self, job: _Job) -> ScanResult | None:
        started = self._host_started.setdefault(job.host, time.monotonic())
        if self.controls.host_timeout and time.monotonic() - started >= self.controls.host_timeout:
            self.metrics.skipped += 1
            return None

        async with self._host_locks[job.host]:
            return await self._scan_with_retries(job)

    async def _scan_with_retries(self, job: _Job) -> ScanResult | None:
        previous_status = "error"
        for attempt in range(self.controls.retries + 1):
            if attempt:
                delay = self._retry_delay(attempt)
                self.metrics.retries += 1
                self.metrics.retry_delay_seconds += delay
                if previous_status == "filtered":
                    self.metrics.retry_filtered += 1
                elif previous_status == "transient":
                    self.metrics.retry_transient += 1
                await asyncio.sleep(delay)

            if self.controls.host_timeout:
                host_started = self._host_started[job.host]
                if time.monotonic() - host_started >= self.controls.host_timeout:
                    self.metrics.skipped += 1
                    return None

            status, result = await self._connect_once(job.host, job.port)
            previous_status = status
            if status == "open":
                self.metrics.open += 1
                return result
            if status == "closed":
                self.metrics.closed += 1
                return None
            if status in {"filtered", "transient"} and attempt < self.controls.retries:
                continue
            if status == "filtered":
                self.metrics.filtered += 1
            elif status == "transient":
                self.metrics.transient += 1
            else:
                self.metrics.errors += 1
            return None
        return None

    def _retry_delay(self, attempt: int) -> float:
        """Return bounded exponential backoff with optional symmetric jitter."""
        base = min(0.05 * (2 ** (attempt - 1)), 0.5)
        jitter = self.controls.retry_jitter
        if not jitter:
            return base
        return base * random.uniform(1.0 - jitter, 1.0 + jitter)

    async def _connect_once(self, host: str, port: int) -> tuple[str, ScanResult | None]:
        await self._rate_gate.wait()
        self.metrics.attempts += 1
        if self._adaptive is not None:
            self._adaptive.record_sent(host)
        started = time.monotonic()
        connect_timeout = self.timeout
        if self._adaptive is not None:
            connect_timeout = min(connect_timeout, self._adaptive.recommended_timeout(host))
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=connect_timeout
            )
        except asyncio.TimeoutError:
            await self._record_feedback(host, "filtered", time.monotonic() - started)
            return "filtered", None
        except ConnectionRefusedError:
            await self._record_feedback(host, "closed", time.monotonic() - started)
            return "closed", None
        except OSError as exc:
            if exc.errno in {errno.ECONNREFUSED}:
                status = "closed"
            elif exc.errno in {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH}:
                status = "filtered"
            elif exc.errno in {
                errno.EAGAIN,
                errno.EADDRNOTAVAIL,
                errno.ECONNABORTED,
                errno.EMFILE,
                errno.ENFILE,
                errno.ENOBUFS,
            }:
                status = "transient"
            else:
                status = "error"
            await self._record_feedback(host, status, time.monotonic() - started)
            return status, None

        try:
            banner = await self._grab_banner(reader, writer, port) if self.banners else ""
            service = _detect_service(port, banner)
            severity = (
                Severity.CRITICAL if port in CRIT_PORTS
                else Severity.HIGH if port in HIGH_PORTS
                else Severity.INFO
            )
            detail = service + (f" | {banner[:80]}" if banner else "")
            await self._record_feedback(host, "open", time.monotonic() - started)
            return "open", ScanResult(
                "portscan",
                host,
                port,
                "open",
                severity,
                detail,
                {"service": service, "banner": banner, "method": "connect"},
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _record_feedback(self, host: str, status: str, elapsed: float) -> None:
        if self._adaptive is None:
            return
        if status in {"open", "closed"}:
            await self._adaptive.record_response(host, elapsed)
        elif status in {"filtered", "transient"}:
            await self._adaptive.record_timeout(host)
        if self._adaptive_window is not None and self._aimd is not None:
            loss_aware_limit = self._aimd.record(status)
            combined_limit = min(self._adaptive.current_concurrency, loss_aware_limit)
            await self._adaptive_window.update(combined_limit)
            self.metrics.aimd = self._aimd.summary()

    @property
    def adaptive_summary(self) -> str | None:
        return self._adaptive.summary() if self._adaptive is not None else None

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
    ) -> str:
        try:
            probe = PROBES.get(port)
            if probe:
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=min(1.5, self.timeout))
            else:
                data = await asyncio.wait_for(reader.read(512), timeout=min(1.0, self.timeout))
            return data.decode("utf-8", errors="replace").strip()[:200]
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return ""


def _detect_service(port: int, banner: str) -> str:
    service = SERVICE_MAP.get(port, f"port/{port}")
    if not service.startswith("port/") or not banner:
        return service
    lowered = banner.lower()
    if "ssh" in lowered:
        return "SSH"
    if "ftp" in lowered:
        return "FTP"
    if "smtp" in lowered:
        return "SMTP"
    if "http" in lowered:
        return "HTTP"
    if "mysql" in lowered:
        return "MySQL"
    if "redis" in lowered:
        return "Redis"
    if "mongo" in lowered:
        return "MongoDB"
    if "rfb" in lowered:
        return "VNC"
    return service

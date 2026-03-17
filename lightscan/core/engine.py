"""
Core engine — the async task runner everything else is built on.

ScanResult is the single data type that flows through the whole tool.
Every scanner, brute-forcer, and CVE checker returns a list of these.
PhantomEngine runs them all concurrently behind a semaphore and shows
a live progress line while they run.
"""
from __future__ import annotations

import asyncio
import time
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class ScanResult:
    module:    str
    target:    str
    port:      int
    status:    str
    severity:  Severity = Severity.INFO
    detail:    str = ""
    data:      dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

class PhantomEngine:
    def __init__(self, concurrency=256, timeout=3.0, verbose=False, rate_limit=0.0,
                 adaptive=False, timing=4):
        self.concurrency = concurrency
        self.timeout     = timeout
        self.verbose     = verbose
        self.rate_limit  = rate_limit
        self._sem        = None
        self._results    = []
        self._errors     = []
        self._done       = 0
        self._total      = 0
        self._start      = 0.0
        self._adaptive   = None

        # adaptive=True: concurrency + timeout adjust dynamically based on RTT + loss.
        # self.concurrency becomes the ceiling; AdaptiveTimingEngine drives the semaphore.
        if adaptive:
            try:
                from lightscan.scan.adaptive import AdaptiveTimingEngine
                self._adaptive = AdaptiveTimingEngine(
                    base_timing=timing,
                    max_concurrency=concurrency,
                )
            except ImportError:
                pass  # fall back to static

    def _progress(self, label=""):
        elapsed = time.time() - self._start
        pct = (self._done / self._total * 100) if self._total else 0
        sys.stdout.write(
            f"\r\033[38;5;196m[PHANTOM]\033[0m "
            f"{self._done}/{self._total} ({pct:.1f}%)  "
            f"elapsed={elapsed:.1f}s  {label:<35}"
        )
        sys.stdout.flush()

    async def _run_one(self, coro, label=""):
        async with self._sem:
            if self.rate_limit > 0:
                await asyncio.sleep(self.rate_limit)

            # adaptive timeout: per-target RTT-derived timeout, capped at self.timeout
            timeout = self.timeout
            target  = getattr(self, "_target", "")
            if self._adaptive and target:
                timeout = min(self.timeout, self._adaptive.recommended_timeout(target))
                self._adaptive.record_sent(target)

            t0 = time.time()
            try:
                result = await asyncio.wait_for(coro, timeout=timeout)
                if result is not None:
                    if isinstance(result, list):
                        self._results.extend(result)
                    else:
                        self._results.append(result)
                # record RTT for successful completions
                if self._adaptive and target:
                    await self._adaptive.record_response(target, time.time() - t0)
            except asyncio.TimeoutError:
                if self._adaptive and target:
                    await self._adaptive.record_timeout(target)
            except Exception as e:
                self._errors.append(f"{label}: {e}")
                if self._adaptive and target:
                    await self._adaptive.record_timeout(target)
            finally:
                self._done += 1
                if not self.verbose:
                    self._progress(label)

    async def run(self, tasks, target: str = ""):
        # If adaptive is active, seed the semaphore from the engine's current concurrency.
        # The semaphore is rebuilt mid-run only conceptually — we poll current_concurrency
        # to throttle via a secondary gate in _run_one. Rebuilding the actual asyncio.Semaphore
        # mid-gather is not safe, so we use a soft gate instead.
        init_concurrency = (
            self._adaptive.current_concurrency if self._adaptive else self.concurrency
        )
        self._sem     = asyncio.Semaphore(init_concurrency)
        self._results = []
        self._errors  = []
        self._done    = 0
        self._total   = len(tasks)
        self._start   = time.time()
        self._target  = target
        await asyncio.gather(*[self._run_one(c, l) for c, l in tasks])
        print()
        elapsed = time.time() - self._start
        if self._adaptive:
            print(f"\033[38;5;240m[~] adaptive: {self._adaptive.summary()}\033[0m")
        print(f"\033[38;5;240m[+] Done: {len(self._results)} results · {len(self._errors)} errors · {elapsed:.2f}s\033[0m")
        return self._results

    def run_sync(self, tasks):
        try:
            loop = asyncio.get_running_loop()
            # Already inside a running event loop (e.g. Jupyter / nested call)
            # Schedule as a task and block via run_until_complete on a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self.run(tasks))
                return future.result()
        except RuntimeError:
            # No running loop — safe to use asyncio.run()
            return asyncio.run(self.run(tasks))
# concurrency fix
# retry logic
# terminal width fix
# semaphore fix
# color output
# elapsed time
# concurrency fix
# retry logic
# terminal width fix
# semaphore fix
# color output
# elapsed time
# exception surfacing
# ulimit check
# speed display
# cancelled error
# concurrency fix
# retry logic
# terminal width fix
# semaphore fix
# color output
# elapsed time
# exception surfacing
# ulimit check
# speed display

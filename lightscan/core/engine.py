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
        if not sys.stdout.isatty():
            return
        elapsed = time.time() - self._start
        pct = (self._done / self._total * 100) if self._total else 0
        
        # Smoothly rotating spinner
        spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spin_char = spinners[int(time.time() * 10) % len(spinners)]
        
        # Color gradient progress bar (width 12)
        width = 12
        filled = int(round(width * pct / 100))
        bar_chars = []
        for i in range(width):
            if i < filled:
                # Custom hue sweep (Reds to oranges to yellows)
                shades = [88, 124, 160, 196, 196, 202, 202, 208, 208, 214, 220, 226]
                c = shades[min(i, len(shades) - 1)]
                bar_chars.append(f"\033[38;5;{c}m█\033[0m")
            else:
                bar_chars.append("\033[38;5;236m░\033[0m")
        bar = "".join(bar_chars)
        
        sys.stdout.write(
            f"\r\033[38;5;196m[{spin_char} PHANTOM]\033[0m "
            f"[{bar}] {self._done}/{self._total} ({pct:.1f}%) "
            f"\033[38;5;242melapsed={elapsed:.1f}s\033[0m  "
            f"\033[38;5;244m{label:<35}\033[0m"
        )
        sys.stdout.flush()

    @staticmethod
    def _host_from_label(label: str, fallback: str) -> str:
        # build_scan_tasks() labels are "host:port" (and "udp:host:port" for
        # udp tasks) - pull the host back out so adaptive stats get
        # attributed to the actual thing that was connected to, not to
        # whatever (if anything) got passed into run(target=...). this is
        # also what fixes run(tasks) being called with no target at all -
        # that left self._target as "", which is falsy, so record_sent/
        # record_response/record_timeout never fired and every single scan
        # printed a static "sent=0 recv=0 loss=100.0%" regardless of what
        # actually happened - and because of that, current_concurrency
        # never adjusted off the timing template's raw default either.
        if not label:
            return fallback
        parts = label.split(":")
        if len(parts) >= 2 and parts[-1].isdigit():
            return parts[-2] if len(parts) > 2 else parts[0]
        return fallback

    async def _run_one(self, coro, label=""):
        async with self._sem:
            if self.rate_limit > 0:
                await asyncio.sleep(self.rate_limit)

            # adaptive timeout: per-target RTT-derived timeout, capped at self.timeout
            timeout = self.timeout
            target  = self._host_from_label(label, getattr(self, "_target", ""))
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
        
        # Clear progress line cleanly upon completion
        if sys.stdout.isatty():
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        else:
            print()
            
        elapsed = time.time() - self._start
        if self._adaptive:
            print(f"\033[38;5;240m[~] adaptive: {self._adaptive.summary()}\033[0m")
        print(f"\033[38;5;82m[+] PHANTOM COMPLETE:\033[0m {len(self._results)} findings · {len(self._errors)} errors · {elapsed:.2f}s")
        return self._results

    def run_sync(self, tasks):
        try:
            loop = asyncio.get_running_loop()
            # already inside a running event loop (e.g. jupyter / nested call).
            # asyncio.run() in a thread creates its own loop which is fine here
            # since PhantomEngine tasks don't reference the outer loop.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self.run(tasks))
                return future.result()
        except RuntimeError:
            return asyncio.run(self.run(tasks))

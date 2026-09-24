"""Shared result record and legacy asynchronous task runner.

New bounded TCP scans use :mod:`lightscan.scan.streaming`; ``ScanResult``
remains the common serialization contract used by all scanner families.
"""
from __future__ import annotations

import asyncio
import time
import sys

from lightscan.core.rate_limit import RateLimiter
from lightscan.core.models import ScanResult, Severity

class PhantomEngine:
    def __init__(self, concurrency=256, timeout=3.0, verbose=False, max_rate=0.0,
                 adaptive=False, timing=4):
        self.concurrency = concurrency
        self.timeout     = timeout
        self.verbose     = verbose
        self.max_rate = max_rate
        self._rate_limiter = RateLimiter(max_rate)
        self._sem        = None
        self._results    = []
        self._errors     = []
        self._done       = 0
        self._total      = 0
        self._start      = 0.0
        self._adaptive   = None

        if adaptive:
            try:
                from lightscan.scan.adaptive import AdaptiveTimingEngine
                self._adaptive = AdaptiveTimingEngine(
                    base_timing=timing,
                    max_concurrency=concurrency,
                )
            except ImportError:
                pass

    def _progress(self, label=""):
        if not sys.stdout.isatty():
            return
        elapsed = time.time() - self._start
        pct = (self._done / self._total * 100) if self._total else 0
        
        spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spin_char = spinners[int(time.time() * 10) % len(spinners)]
        
        width = 12
        filled = int(round(width * pct / 100))
        bar_chars = []
        for i in range(width):
            if i < filled:
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
        if not label:
            return fallback
        parts = label.split(":")
        if len(parts) >= 2 and parts[-1].isdigit():
            return parts[-2] if len(parts) > 2 else parts[0]
        return fallback

    async def _run_one(self, coro, label=""):
        async with self._sem:
            await self._rate_limiter.acquire()

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
        
        if sys.stdout.isatty():
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        else:
            print()
            
        elapsed = time.time() - self._start
        if self._adaptive:
            print(f"\033[38;5;240m[~] adaptive: {self._adaptive.summary()}\033[0m")
        print(f"\033[38;5;82m[+] LIGHTSCAN COMPLETE:\033[0m {len(self._results)} findings · {len(self._errors)} errors · {elapsed:.2f}s")
        return self._results

    def run_sync(self, tasks):
        try:
            loop = asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self.run(tasks))
                return future.result()
        except RuntimeError:
            return asyncio.run(self.run(tasks))

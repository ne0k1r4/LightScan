# core/engine.py — scan engine v0.2
# Light
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ScanResult:
    module:   str
    host:     str
    port:     int
    service:  str
    severity: Severity
    detail:   str = ""


class PhantomEngine:
    def __init__(self, concurrency=100, timeout=1.0, verbose=False):
        self.concurrency = concurrency
        self.timeout     = timeout
        self.verbose     = verbose
        self._results    = []
        self._done       = 0
        self._total      = 0

    async def run(self, tasks):
        sem = asyncio.Semaphore(self.concurrency)
        self._results = []
        self._done    = 0
        self._total   = len(tasks)

        async def _one(coro, label=""):
            async with sem:
                try:
                    r = await asyncio.wait_for(coro, timeout=self.timeout)
                    if r:
                        if isinstance(r, list):
                            self._results.extend(r)
                        else:
                            self._results.append(r)
                except Exception:
                    pass
                finally:
                    self._done += 1
                    print(f"\r[{self._done}/{self._total}]", end="", flush=True)

        await asyncio.gather(*[_one(c, l) for c, l in tasks])
        print()
        return self._results

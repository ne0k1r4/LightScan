"""Async connection-start rate limiting shared by scanner implementations."""
from __future__ import annotations

import asyncio
import math
import time


class RateLimiter:
    """Space operation starts at no more than *rate* starts per second.

    A non-positive rate disables limiting. The limiter is process-local and is
    intended to be shared by every worker participating in one scan.
    """

    def __init__(self, rate: float = 0.0) -> None:
        if not math.isfinite(rate) or rate < 0:
            raise ValueError("rate must be finite and non-negative")
        self._interval = 1.0 / rate if rate else 0.0
        self._lock = asyncio.Lock()
        self._next_start = 0.0

    async def acquire(self) -> None:
        """Wait until this operation is allowed to start."""
        if not self._interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next_start - now
            if delay > 0:
                await asyncio.sleep(delay)
            # Advance from the actual grant time. Holding the lock through the
            # wait prevents delayed event-loop wakeups from bunching grants.
            self._next_start = time.monotonic() + self._interval

"""A small, explicit AIMD controller for bounded TCP scan concurrency.

The controller is deliberately deterministic: a loss-like result halves the
window immediately, while only sustained response outcomes earn one additional
slot. It complements RTT estimation by controlling how many new attempts are
in flight when the scanner observes congestion or local transient pressure.
"""
from __future__ import annotations

from dataclasses import dataclass


LOSS_STATUSES = frozenset({"filtered", "transient"})
SUCCESS_STATUSES = frozenset({"open", "closed"})


@dataclass
class AimdConcurrencyController:
    """Bound an active concurrency window using additive increase and multiplicative decrease."""

    initial: int
    maximum: int
    minimum: int = 1
    increase_every: int = 16

    def __post_init__(self) -> None:
        if self.minimum < 1:
            raise ValueError("minimum must be at least 1")
        if self.maximum < self.minimum:
            raise ValueError("maximum must be greater than or equal to minimum")
        if not self.minimum <= self.initial <= self.maximum:
            raise ValueError("initial must be within the configured window")
        if self.increase_every < 1:
            raise ValueError("increase_every must be at least 1")
        self.current = self.initial
        self._stable_responses = 0
        self.increases = 0
        self.decreases = 0

    def record(self, status: str) -> int:
        """Record one classified outcome and return the recommended window size."""
        if status in LOSS_STATUSES:
            next_window = max(self.minimum, self.current // 2)
            if next_window < self.current:
                self.decreases += 1
            self.current = next_window
            self._stable_responses = 0
        elif status in SUCCESS_STATUSES:
            self._stable_responses += 1
            if self._stable_responses >= self.increase_every and self.current < self.maximum:
                self.current += 1
                self.increases += 1
                self._stable_responses = 0
        return self.current

    def summary(self) -> dict[str, int]:
        """Return compact controller evidence for scan metrics and reports."""
        return {
            "current": self.current,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "increases": self.increases,
            "decreases": self.decreases,
            "stable_responses": self._stable_responses,
        }

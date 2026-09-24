"""Shared scan result types used by scanners and report writers."""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScanResult:
    """One scanner observation in the existing report compatibility format.

    ``status`` is intentionally a string: port state, protocol observations,
    and vulnerability checks currently use distinct vocabularies. ``data``
    carries structured evidence while ``detail`` remains a display summary.
    """

    module: str
    target: str
    port: int
    status: str
    severity: Severity = Severity.INFO
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON-compatible representation."""
        result = asdict(self)
        result["severity"] = self.severity.value
        return result

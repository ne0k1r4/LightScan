"""
LightScan
Developer: Light (Neok1ra)
"""
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


class Confidence(str, Enum):
    CERTAIN = "CERTAIN"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"


@dataclass
class ScanResult:

    module: str
    target: str
    port: int
    status: str
    severity: Severity = Severity.INFO
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    confidence: Confidence = Confidence.FIRM
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""

    def __post_init__(self):
        if not self.cwe or not self.owasp or not self.remediation:
            from lightscan.core.taxonomy import get_taxonomy
            meta = get_taxonomy(self.module)
            if not self.cwe:
                self.cwe = meta.get("cwe", "")
            if not self.owasp:
                self.owasp = meta.get("owasp", "")
            if not self.remediation:
                self.remediation = meta.get("remediation", "")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        result["confidence"] = self.confidence.value if isinstance(self.confidence, Confidence) else str(self.confidence)
        return result

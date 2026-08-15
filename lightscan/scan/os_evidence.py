"""Conservative OS-family inference from already collected service evidence.

The rules in this module are independently authored from vendor/product strings
already observed by LightScan service probes or imported inventory artifacts.
They do not reproduce probe fingerprints or signature data from third parties,
and they never initiate a network connection.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from lightscan.core.engine import ScanResult, Severity


@dataclass(frozen=True)
class _EvidenceRule:
    family: str
    pattern: str
    weight: int
    label: str


# Each rule is intentionally specific. Generic products such as Apache and nginx
# are excluded because they do not safely identify the operating-system family.
_RULES: tuple[_EvidenceRule, ...] = (
    _EvidenceRule("Windows", "openssh_for_windows", 85, "OpenSSH for Windows"),
    _EvidenceRule("Windows", "microsoft-iis", 80, "Microsoft IIS"),
    _EvidenceRule("Windows", "microsoft windows", 80, "Microsoft Windows"),
    _EvidenceRule("Linux", "ubuntu", 75, "Ubuntu"),
    _EvidenceRule("Linux", "debian", 75, "Debian"),
    _EvidenceRule("Linux", "raspbian", 75, "Raspbian"),
    _EvidenceRule("Linux", "red hat", 75, "Red Hat"),
    _EvidenceRule("Linux", "rhel", 70, "RHEL"),
    _EvidenceRule("Linux", "rocky linux", 75, "Rocky Linux"),
    _EvidenceRule("Linux", "almalinux", 75, "AlmaLinux"),
    _EvidenceRule("Linux", "fedora", 75, "Fedora"),
    _EvidenceRule("Linux", "alpine linux", 75, "Alpine Linux"),
    _EvidenceRule("FreeBSD", "freebsd", 80, "FreeBSD"),
    _EvidenceRule("OpenBSD", "openbsd", 80, "OpenBSD"),
    _EvidenceRule("NetBSD", "netbsd", 80, "NetBSD"),
    _EvidenceRule("macOS", "mac os x", 80, "Mac OS X"),
    _EvidenceRule("macOS", "darwin", 75, "Darwin"),
    _EvidenceRule("Cisco IOS", "cisco ios", 85, "Cisco IOS"),
    _EvidenceRule("Cisco IOS", "cisco nx-os", 85, "Cisco NX-OS"),
    _EvidenceRule("Juniper Junos", "juniper junos", 85, "Juniper Junos"),
)


def _candidate_text(result: ScanResult) -> str:
    """Join only existing textual evidence fields from one result."""
    values = [result.detail]
    for key in ("service", "name", "product", "version", "raw", "extrainfo"):
        value = result.data.get(key)
        if isinstance(value, str):
            values.append(value)
    return " ".join(values).casefold()


def _result_source(result: ScanResult) -> str:
    if result.module == "nmap-service-import":
        return "Nmap XML service evidence"
    if result.module == "service-version":
        return "LightScan service probe"
    return result.module


def _confidence(score: int, source_count: int) -> str:
    if score >= 85 and source_count >= 2:
        return "HIGH"
    if score >= 70:
        return "MEDIUM"
    return "LOW"


def infer_os_from_results(results: Iterable[ScanResult]) -> list[ScanResult]:
    """Infer one conservative OS-family result per target from existing evidence.

    Only `service-version` and `nmap-service-import` records contribute. A result
    requires a distinctive vendor or product match, and its score is capped rather
    than treating duplicated service banners as independent proof.
    """
    findings: list[ScanResult] = []
    per_target: dict[str, list[ScanResult]] = defaultdict(list)
    for result in results:
        if result.module in {"service-version", "nmap-service-import"}:
            per_target[result.target].append(result)

    for target, target_results in sorted(per_target.items()):
        matched: dict[str, list[dict[str, object]]] = defaultdict(list)
        for result in target_results:
            text = _candidate_text(result)
            for rule in _RULES:
                if rule.pattern not in text:
                    continue
                matched[rule.family].append(
                    {
                        "port": result.port,
                        "source": _result_source(result),
                        "signal": rule.label,
                        "weight": rule.weight,
                    }
                )

        candidates: list[dict[str, object]] = []
        for family, observations in matched.items():
            # De-duplicate by port/signal so a raw banner and normalized product
            # on the same service cannot inflate confidence.
            unique: dict[tuple[int, str], dict[str, object]] = {}
            for observation in observations:
                unique[(int(observation["port"]), str(observation["signal"]))] = observation
            evidence = list(unique.values())
            score = min(95, max(int(item["weight"]) for item in evidence) + 10 * (len(evidence) - 1))
            candidates.append(
                {
                    "family": family,
                    "score": score,
                    "confidence": _confidence(score, len(evidence)),
                    "evidence": sorted(evidence, key=lambda item: (int(item["port"]), str(item["signal"]))),
                }
            )

        if not candidates:
            continue
        candidates.sort(key=lambda item: (-int(item["score"]), str(item["family"])))
        best = candidates[0]
        evidence = best["evidence"]
        assert isinstance(evidence, list)
        signals = ", ".join(f"{item['signal']} on {item['port']}" for item in evidence)
        detail = (
            f"OS-family inference: {best['family']} confidence={best['confidence']} "
            f"score={best['score']}/95 from {signals}"
        )
        findings.append(
            ScanResult(
                module="os-evidence",
                target=target,
                port=0,
                status="observed",
                severity=Severity.INFO,
                detail=detail,
                data={
                    "method": "existing-service-evidence",
                    "family": best["family"],
                    "confidence": best["confidence"],
                    "score": best["score"],
                    "max_score": 95,
                    "evidence": evidence,
                    "alternatives": candidates[1:3],
                },
            )
        )
    return findings

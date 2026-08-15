from __future__ import annotations

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.os_evidence import infer_os_from_results


def service_result(target: str, port: int, version: str, *, raw: str = "") -> ScanResult:
    return ScanResult(
        "service-version",
        target,
        port,
        "open",
        Severity.INFO,
        version,
        {"service": "SSH", "version": version, "raw": raw},
    )


def test_os_evidence_uses_distinctive_existing_service_signals() -> None:
    results = [
        service_result("192.0.2.10", 22, "OpenSSH_9.6p1 Ubuntu-3ubuntu13"),
        ScanResult(
            "nmap-service-import",
            "192.0.2.10",
            443,
            "open",
            Severity.INFO,
            "Imported Nmap service observation: https (Ubuntu)",
            {"product": "Ubuntu Apache"},
        ),
    ]

    inferred = infer_os_from_results(results)

    assert len(inferred) == 1
    finding = inferred[0]
    assert finding.target == "192.0.2.10"
    assert finding.module == "os-evidence"
    assert finding.data["method"] == "existing-service-evidence"
    assert finding.data["family"] == "Linux"
    assert finding.data["confidence"] == "HIGH"
    assert finding.data["score"] == 85
    assert [item["port"] for item in finding.data["evidence"]] == [22, 443]


def test_os_evidence_does_not_infer_from_generic_products() -> None:
    results = [
        service_result("192.0.2.11", 22, "OpenSSH_9.6p1"),
        ScanResult(
            "nmap-service-import",
            "192.0.2.11",
            80,
            "open",
            Severity.INFO,
            "Imported Nmap service observation: http (nginx)",
            {"product": "nginx"},
        ),
    ]

    assert infer_os_from_results(results) == []


def test_os_evidence_caps_duplicate_signals_on_one_port() -> None:
    results = [
        service_result(
            "2001:db8::20",
            22,
            "OpenSSH_for_Windows_9.5",
            raw="SSH-2.0-OpenSSH_for_Windows_9.5",
        )
    ]

    inferred = infer_os_from_results(results)

    assert len(inferred) == 1
    finding = inferred[0]
    assert finding.data["family"] == "Windows"
    assert finding.data["confidence"] == "MEDIUM"
    assert finding.data["score"] == 85
    assert len(finding.data["evidence"]) == 1

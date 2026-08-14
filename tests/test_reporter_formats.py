"""Tests for structured and safe report serialization."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from lightscan.core.engine import ScanResult, Severity
from lightscan.core.reporter import Reporter


def _sample_results() -> list[ScanResult]:
    return [
        ScanResult(
            "portscan",
            "192.0.2.10",
            22,
            "open",
            Severity.INFO,
            "SSH | SSH-2.0-OpenSSH_9.8",
            {"service": "SSH", "banner": "SSH-2.0-OpenSSH_9.8"},
        ),
        ScanResult(
            "service-version",
            "192.0.2.10",
            22,
            "open",
            Severity.INFO,
            "SSH OpenSSH_9.8",
            {"service": "SSH", "version": "OpenSSH_9.8", "method": "probed", "confidence": 10},
        ),
        ScanResult(
            "weak-configuration",
            "192.0.2.10",
            22,
            "open",
            Severity.HIGH,
            "Legacy key exchange enabled",
            {"evidence": "diffie-hellman-group1-sha1"},
        ),
    ]


def test_json_report_preserves_result_data(tmp_path):
    path = tmp_path / "report.json"
    Reporter()._write_json(str(path), _sample_results(), {"timestamp": 1})

    document = json.loads(path.read_text())
    assert document["results"][1]["data"]["method"] == "probed"
    assert document["results"][2]["status"] == "open"


def test_nmap_xml_prefers_probe_service_metadata_and_keeps_findings_as_scripts(tmp_path):
    path = tmp_path / "report.xml"
    Reporter()._write_nmap_xml(str(path), _sample_results(), {"timestamp": 1, "command": "lightscan --scan"})

    root = ET.parse(path).getroot()
    service = root.find("./host/ports/port/service")
    script = root.find("./host/ports/port/script")

    assert root.attrib["scanner"] == "lightscan"
    assert service is not None
    assert service.attrib["name"] == "ssh"
    assert service.attrib["version"] == "OpenSSH_9.8"
    assert service.attrib["method"] == "probed"
    assert script is not None
    assert script.attrib["id"] == "weak-configuration"
    assert root.find("./runstats/hosts").attrib["up"] == "1"


def test_html_report_escapes_untrusted_banner_text(tmp_path):
    path = tmp_path / "report.html"
    results = [
        ScanResult(
            "portscan",
            "192.0.2.10",
            80,
            "open",
            Severity.INFO,
            "<script>alert('banner')</script>",
        )
    ]
    Reporter()._write_html(str(path), results, {})

    document = path.read_text()
    assert "&lt;script&gt;" in document
    assert "<script>alert('banner')</script>" not in document

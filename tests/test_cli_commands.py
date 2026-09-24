from __future__ import annotations

import json
from pathlib import Path

import pytest

from lightscan.commands.parser import build_parser, normalize_command_argv
from lightscan.commands.report import _load_report, main as report_main
from lightscan.core.target import parse_ports, parse_targets
from lightscan.core.models import Severity


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("scan", ["--scan", "-t", "192.0.2.1", "-p", "80"]),
        ("services", ["--scan", "--sv", "-t", "192.0.2.1"]),
        ("web", ["--web-scan", "https://example.test"]),
        ("dns", ["--dns", "example.test"]),
    ],
)
def test_command_forms_preserve_legacy_options(command, expected):
    target = {
        "scan": "192.0.2.1",
        "services": "192.0.2.1",
        "web": "https://example.test",
        "dns": "example.test",
    }[command]
    options = ["-p", "80"] if command == "scan" else []
    assert normalize_command_argv([command, target, *options]) == expected


def test_unknown_and_legacy_option_forms_are_unchanged():
    argv = ["--scan", "-t", "192.0.2.1"]
    assert normalize_command_argv(argv) is argv


def test_focused_commands_parse_into_existing_scan_options():
    args = build_parser().parse_args(
        normalize_command_argv(["services", "192.0.2.1", "-p", "22,443"])
    )
    assert args.scan is True
    assert args.sv is True
    assert args.target == "192.0.2.1"
    assert args.ports == "22,443"


def test_report_loader_restores_shared_result_model(tmp_path):
    report = tmp_path / "input.json"
    report.write_text(
        json.dumps(
            {
                "meta": {"target": "192.0.2.1"},
                "results": [
                    {
                        "module": "portscan",
                        "target": "192.0.2.1",
                        "port": 443,
                        "status": "open",
                        "severity": "INFO",
                        "detail": "HTTPS",
                        "data": {"service": "HTTPS"},
                        "timestamp": 10.0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    results, meta = _load_report(str(report))

    assert meta["target"] == "192.0.2.1"
    assert results[0].severity is Severity.INFO
    assert results[0].data["service"] == "HTTPS"


def test_report_loader_rejects_unknown_severity(tmp_path):
    report = tmp_path / "invalid.json"
    report.write_text('{"meta": {}, "results": [{"module":"x", "status":"open", "severity":"wat"}]}')
    with pytest.raises(ValueError, match="invalid result"):
        _load_report(str(report))


def test_report_command_converts_json_to_html(tmp_path):
    source = tmp_path / "input.json"
    source.write_text(
        json.dumps({"meta": {}, "results": [{"module": "portscan", "target": "192.0.2.1", "port": 443, "status": "open"}]}),
        encoding="utf-8",
    )
    output = tmp_path / "out"

    assert report_main([str(source), "--format", "html", "--output", str(output)]) == 0
    assert list(output.glob("*.html"))


def test_python_engine_obeys_shared_target_and_port_fixture():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "engine_inputs.json").read_text()
    )
    assert parse_targets(fixture["target"], max_targets=fixture["max_targets"]) == fixture["expected_hosts"]
    assert parse_ports(fixture["ports"]) == fixture["expected_ports"]

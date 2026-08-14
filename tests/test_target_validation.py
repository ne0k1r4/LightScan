"""Regression tests for target and port input validation."""
from __future__ import annotations

import pytest

from lightscan.core.target import TargetSpecError, parse_ports, parse_targets


def test_cidr_expansion_is_bounded_before_iteration():
    with pytest.raises(TargetSpecError, match="above the 1,024 target limit"):
        parse_targets("10.0.0.0/8", max_targets=1_024)


def test_target_file_supports_comments_and_deduplicates_entries(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("# approved scope\n192.0.2.10\n192.0.2.10\n192.0.2.11\n")

    assert parse_targets(f"file:{targets}") == ["192.0.2.10", "192.0.2.11"]


def test_invalid_last_octet_range_is_rejected():
    with pytest.raises(TargetSpecError, match="invalid IPv4 range"):
        parse_targets("192.0.2.250-300")


def test_file_errors_include_the_source_line(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("192.0.2.10\n192.0.2.0/8\n")

    with pytest.raises(TargetSpecError, match=r"targets.txt:2"):
        parse_targets(f"file:{targets}", max_targets=10)


@pytest.mark.parametrize(
    ("specification", "expected"),
    [
        ("22,80,443", [22, 80, 443]),
        ("22-24,80,22", [22, 23, 24, 80]),
        ("top-100", parse_ports("top100")),
    ],
)
def test_port_parser_accepts_valid_deduplicated_specs(specification, expected):
    assert parse_ports(specification) == expected


@pytest.mark.parametrize("specification", ["", "0", "65536", "443-80", "80,,443", "http"])
def test_port_parser_rejects_malformed_or_out_of_range_specs(specification):
    with pytest.raises(TargetSpecError):
        parse_ports(specification)

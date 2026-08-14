"""Target and port parsing utilities for bounded, predictable scan planning.

The parser accepts single addresses, CIDRs, simple IPv4 last-octet ranges,
hostnames, stdin, and ``file:`` target lists.  It deliberately expands input
before any network traffic is sent so callers can validate scope and workload
up front.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path

TOP_100 = sorted(
    {
        20, 21, 22, 23, 25, 53, 69, 79, 80, 88, 110, 111, 119, 123, 135,
        137, 138, 139, 143, 161, 194, 389, 443, 445, 465, 514, 515, 548,
        587, 631, 636, 873, 990, 993, 995, 1080, 1433, 1521, 1723, 2049,
        2082, 2083, 2086, 2087, 3000, 3128, 3306, 3389, 4443, 4848, 5000,
        5432, 5800, 5900, 6379, 6443, 7001, 7443, 8000, 8080, 8081, 8443,
        8888, 9000, 9090, 9200, 9300, 9443, 10000, 27017,
    }
)

DEFAULT_MAX_TARGETS = 65_536
_RANGE_RE = re.compile(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$")


class TargetSpecError(ValueError):
    """Raised when a target or port specification is invalid or unsafe."""


def parse_targets(spec: str, *, max_targets: int = DEFAULT_MAX_TARGETS) -> list[str]:
    """Expand *spec* into unique targets while enforcing a workload ceiling.

    ``max_targets`` limits the total expanded targets, including entries read
    from stdin or a file.  Operators can use this deterministic preflight to
    avoid accidentally turning a broad CIDR into an unbounded scan.
    """
    if max_targets < 1:
        raise TargetSpecError("max_targets must be at least 1")

    targets = _parse_target_spec(spec, max_targets=max_targets)
    unique = list(dict.fromkeys(targets))
    if not unique:
        raise TargetSpecError("target specification did not contain any targets")
    return unique


def _parse_target_spec(spec: str, *, max_targets: int) -> list[str]:
    spec = (spec or "").strip()
    if not spec:
        raise TargetSpecError("target specification cannot be empty")

    if spec == "-":
        import sys

        return _parse_target_lines(sys.stdin, source="stdin", max_targets=max_targets)

    if spec.startswith("file:"):
        path = Path(spec[5:]).expanduser()
        try:
            with path.open(encoding="utf-8") as handle:
                return _parse_target_lines(handle, source=str(path), max_targets=max_targets)
        except OSError as exc:
            raise TargetSpecError(f"unable to read target file {path}: {exc}") from exc

    if "/" in spec:
        try:
            network = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            # A hostname may legally include a slash only in an invalid input;
            # make the failure explicit rather than passing it to the scanner.
            raise TargetSpecError(f"invalid CIDR target: {spec!r}") from None
        count = _host_count(network)
        _ensure_limit(count, max_targets, spec)
        return [str(host) for host in network.hosts()]

    range_match = _RANGE_RE.fullmatch(spec)
    if range_match:
        prefix, start_raw, end_raw = range_match.groups()
        start, end = int(start_raw), int(end_raw)
        if not 0 <= start <= 255 or not 0 <= end <= 255 or start > end:
            raise TargetSpecError(f"invalid IPv4 range: {spec!r}")
        _ensure_limit(end - start + 1, max_targets, spec)
        return [f"{prefix}{octet}" for octet in range(start, end + 1)]

    try:
        return [str(ipaddress.ip_address(spec))]
    except ValueError:
        if any(char.isspace() for char in spec):
            raise TargetSpecError(f"invalid hostname target: {spec!r}")
        return [spec]


def _parse_target_lines(lines, *, source: str, max_targets: int) -> list[str]:
    targets: list[str] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        remaining = max_targets - len(targets)
        if remaining < 1:
            raise TargetSpecError(
                f"target limit of {max_targets:,} exceeded while reading {source}"
            )
        try:
            targets.extend(_parse_target_spec(line, max_targets=remaining))
        except TargetSpecError as exc:
            raise TargetSpecError(f"{source}:{line_number}: {exc}") from exc
    _ensure_limit(len(targets), max_targets, source)
    return targets


def _host_count(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    if network.version == 4 and network.prefixlen <= 30:
        return max(network.num_addresses - 2, 0)
    return network.num_addresses


def _ensure_limit(count: int, maximum: int, source: str) -> None:
    if count > maximum:
        raise TargetSpecError(
            f"{source!r} expands to {count:,} targets, above the {maximum:,} target limit"
        )


def parse_ports(spec: str) -> list[int]:
    """Parse a comma-separated port list and reject invalid or empty input."""
    normalized = (spec or "").strip().lower()
    if normalized in {"top100", "top-100"}:
        return TOP_100.copy()
    if not normalized:
        raise TargetSpecError("port specification cannot be empty")

    ports: set[int] = set()
    for raw_part in normalized.split(","):
        part = raw_part.strip()
        if not part:
            raise TargetSpecError(f"empty port entry in {spec!r}")
        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) != 2 or not all(bound.isdigit() for bound in bounds):
                raise TargetSpecError(f"invalid port range: {part!r}")
            start, end = (int(bound) for bound in bounds)
            if start > end:
                raise TargetSpecError(f"invalid descending port range: {part!r}")
            _validate_port(start)
            _validate_port(end)
            ports.update(range(start, end + 1))
            continue
        if not part.isdigit():
            raise TargetSpecError(f"invalid port value: {part!r}")
        port = int(part)
        _validate_port(port)
        ports.add(port)

    if not ports:
        raise TargetSpecError("port specification did not contain any ports")
    return sorted(ports)


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65_535:
        raise TargetSpecError(f"port must be between 1 and 65535, got {port}")


def resolve(host: str) -> str | None:
    """Resolve a hostname to IPv4 without raising for an unavailable name."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

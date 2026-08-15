"""Read-only import of OS and service observations from Nmap XML output.

This module deliberately consumes a user-provided scan artifact. It neither executes
Nmap nor vendors Nmap fingerprint databases, so LightScan can correlate approved
inventory evidence without inheriting Nmap's probe behavior or data licensing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from lightscan.core.engine import ScanResult, Severity


MAX_NMAP_XML_BYTES = 64 * 1024 * 1024


class NmapXMLImportError(ValueError):
    """Raised when an Nmap XML artifact is unsafe or does not match the schema."""


def _tag_name(element: ET.Element) -> str:
    """Return an XML element name without an optional namespace prefix."""
    return element.tag.rsplit("}", 1)[-1]


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element if _tag_name(child) == name]


def _first_child(element: ET.Element, name: str) -> ET.Element | None:
    children = _children(element, name)
    return children[0] if children else None


def _bounded_text(value: str | None, limit: int = 512) -> str:
    """Normalize untrusted XML text before it reaches reports or terminal output."""
    return (value or "").strip().replace("\x00", "")[:limit]


def _parse_accuracy(raw: str | None) -> int | None:
    try:
        value = int(raw or "")
    except ValueError:
        return None
    return value if 0 <= value <= 100 else None


def _primary_target(host: ET.Element) -> str | None:
    addresses = _children(host, "address")
    for address_type in ("ipv4", "ipv6"):
        for address in addresses:
            if address.get("addrtype") == address_type and address.get("addr"):
                return _bounded_text(address.get("addr"), 128)

    hostnames = _first_child(host, "hostnames")
    if hostnames is not None:
        hostname = _first_child(hostnames, "hostname")
        if hostname is not None and hostname.get("name"):
            return _bounded_text(hostname.get("name"), 255)
    return None


def _collect_cpes(element: ET.Element) -> list[str]:
    cpes: list[str] = []
    for child in element.iter():
        if _tag_name(child) != "cpe":
            continue
        value = _bounded_text(child.text, 512)
        if value and value not in cpes:
            cpes.append(value)
    return cpes


def _import_os_matches(host: ET.Element, target: str) -> list[ScanResult]:
    os_section = _first_child(host, "os")
    if os_section is None:
        return []

    results: list[ScanResult] = []
    for match in _children(os_section, "osmatch"):
        name = _bounded_text(match.get("name"), 255)
        if not name:
            continue
        accuracy = _parse_accuracy(match.get("accuracy"))
        classes: list[dict[str, str]] = []
        for os_class in _children(match, "osclass"):
            classes.append(
                {
                    key: _bounded_text(os_class.get(key), 128)
                    for key in ("vendor", "osfamily", "osgen", "type")
                    if _bounded_text(os_class.get(key), 128)
                }
            )
        detail = f"Imported Nmap OS observation: {name}"
        if accuracy is not None:
            detail += f" (reported accuracy={accuracy}%)"
        results.append(
            ScanResult(
                module="nmap-os-import",
                target=target,
                port=0,
                status="observed",
                severity=Severity.INFO,
                detail=detail,
                data={
                    "source": "nmap-xml",
                    "name": name,
                    "reported_accuracy": accuracy,
                    "classes": classes,
                    "cpes": _collect_cpes(match),
                },
            )
        )
    return results


def _import_open_services(host: ET.Element, target: str) -> list[ScanResult]:
    ports_section = _first_child(host, "ports")
    if ports_section is None:
        return []

    results: list[ScanResult] = []
    for port_node in _children(ports_section, "port"):
        try:
            port = int(port_node.get("portid", ""))
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        state = _first_child(port_node, "state")
        state_name = _bounded_text(state.get("state") if state is not None else "")
        if state_name not in {"open", "open|filtered"}:
            continue
        service = _first_child(port_node, "service")
        service_data: dict[str, Any] = {
            "source": "nmap-xml",
            "protocol": _bounded_text(port_node.get("protocol"), 32),
            "state": state_name,
        }
        if state is not None and state.get("reason"):
            service_data["state_reason"] = _bounded_text(state.get("reason"), 128)
        if service is not None:
            for key in ("name", "product", "version", "extrainfo", "method", "conf"):
                value = _bounded_text(service.get(key), 255)
                if value:
                    service_data[key] = value
            cpes = _collect_cpes(service)
            if cpes:
                service_data["cpes"] = cpes

        label = service_data.get("name", "unknown")
        product = " ".join(
            str(service_data[key]) for key in ("product", "version") if service_data.get(key)
        )
        detail = f"Imported Nmap service observation: {label}"
        if product:
            detail += f" ({product})"
        results.append(
            ScanResult(
                module="nmap-service-import",
                target=target,
                port=port,
                status=state_name,
                severity=Severity.INFO,
                detail=detail,
                data=service_data,
            )
        )
    return results


def import_nmap_xml(path: str | Path) -> tuple[list[ScanResult], dict[str, int | str]]:
    """Import OS matches and open-service records from one Nmap XML artifact.

    The importer is intentionally offline. XML declarations with DTD or entity
    definitions are rejected before parsing, and only open or open|filtered
    services become LightScan results to keep inventory reports focused.
    """
    source = Path(path).expanduser()
    try:
        size = source.stat().st_size
    except OSError as exc:
        raise NmapXMLImportError(f"Unable to read Nmap XML file: {exc}") from exc
    if not source.is_file():
        raise NmapXMLImportError("Nmap XML input must be a regular file.")
    if size > MAX_NMAP_XML_BYTES:
        raise NmapXMLImportError(
            f"Nmap XML input exceeds the {MAX_NMAP_XML_BYTES // (1024 * 1024)} MiB safety limit."
        )

    try:
        payload = source.read_bytes()
    except OSError as exc:
        raise NmapXMLImportError(f"Unable to read Nmap XML file: {exc}") from exc
    upper_payload = payload.upper()
    if b"<!DOCTYPE" in upper_payload or b"<!ENTITY" in upper_payload:
        raise NmapXMLImportError("Nmap XML containing DTD or entity declarations is not accepted.")

    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise NmapXMLImportError(f"Invalid Nmap XML: {exc}") from exc
    if _tag_name(root) != "nmaprun":
        raise NmapXMLImportError("Expected an Nmap XML document with an <nmaprun> root element.")

    results: list[ScanResult] = []
    hosts_seen = 0
    hosts_imported = 0
    os_observations = 0
    service_observations = 0
    for host in _children(root, "host"):
        hosts_seen += 1
        target = _primary_target(host)
        if not target:
            continue
        hosts_imported += 1
        os_results = _import_os_matches(host, target)
        service_results = _import_open_services(host, target)
        os_observations += len(os_results)
        service_observations += len(service_results)
        results.extend(os_results)
        results.extend(service_results)

    return results, {
        "source": "nmap-xml",
        "path": str(source),
        "hosts_seen": hosts_seen,
        "hosts_imported": hosts_imported,
        "os_observations": os_observations,
        "service_observations": service_observations,
    }

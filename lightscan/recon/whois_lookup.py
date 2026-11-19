"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations

import asyncio
import re
import socket
from datetime import datetime, timezone

from lightscan.core.models import Confidence, ScanResult, Severity


def _whois_query(server: str, domain: str, timeout: float) -> str:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall((domain + "\r\n").encode())
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        return buf.decode("utf-8", "replace")
    except Exception:
        return ""


def _find_field(text: str, *patterns: str) -> str:
    for pat in patterns:
        m = re.search(rf"(?i)^\s*{pat}\s*:\s*(.+)$", text, re.MULTILINE)
        if m:
            return m.group(1).strip()
    return ""


def _parse_whois(raw: str) -> dict:
    parsed: dict = {}
    parsed["registrar"] = _find_field(raw, "Registrar", "registrar")
    parsed["creation_date"] = _find_field(raw, "Creation Date", "Created", "created")
    parsed["expiration_date"] = _find_field(
        raw, "Registrar Registration Expiration Date",
        "Registry Expiry Date", "Expiration Date", "Expiry Date", "paid-till",
    )
    ns_lines = re.findall(r"(?im)^\s*Name Server\s*:\s*(.+)$", raw)
    parsed["name_servers"] = [ns.strip().lower() for ns in ns_lines]
    parsed["dnssec"] = _find_field(raw, "DNSSEC")
    parsed["registrant_org"] = _find_field(
        raw, "Registrant Organization", "Registrant Organisation", "org",
    )
    parsed["registrant_country"] = _find_field(
        raw, "Registrant Country", "Registrant State/Province",
    )
    return parsed


def _parse_date(date_str: str) -> datetime | None:
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
    ):
        try:
            return datetime.strptime(date_str.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _is_privacy_proxy(raw: str) -> bool:
    indicators = [
        "privacy", "proxy", "redacted", "whoisguard",
        "domains by proxy", "contact privacy", "withheld",
        "data protected", "gdpr masked",
    ]
    lower = raw.lower()
    return any(ind in lower for ind in indicators)


def _blocking_whois(domain: str, timeout: float) -> tuple[str, dict]:
    raw = _whois_query("whois.iana.org", domain, timeout)
    if not raw:
        return "", {}

    refer = _find_field(raw, "refer", "whois")
    if refer:
        referred = _whois_query(refer, domain, timeout)
        if referred:
            raw = referred

    parsed = _parse_whois(raw)
    return raw, parsed


async def whois_lookup_async(
    domain: str,
    timeout: float = 10.0,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    try:
        raw, parsed = await asyncio.to_thread(_blocking_whois, domain, timeout)
    except Exception:
        return results

    if not raw:
        results.append(ScanResult(
            module="recon-whois",
            target=domain,
            port=43,
            status="error",
            severity=Severity.INFO,
            detail=f"WHOIS lookup failed for {domain}",
            confidence=Confidence.TENTATIVE,
        ))
        return results

    summary_parts = []
    if parsed.get("registrar"):
        summary_parts.append(f"Registrar: {parsed['registrar']}")
    if parsed.get("creation_date"):
        summary_parts.append(f"Created: {parsed['creation_date']}")
    if parsed.get("expiration_date"):
        summary_parts.append(f"Expires: {parsed['expiration_date']}")
    if parsed.get("name_servers"):
        summary_parts.append(f"NS: {', '.join(parsed['name_servers'][:4])}")
    if parsed.get("dnssec"):
        summary_parts.append(f"DNSSEC: {parsed['dnssec']}")
    if parsed.get("registrant_org"):
        summary_parts.append(f"Org: {parsed['registrant_org']}")

    detail = "; ".join(summary_parts) if summary_parts else f"WHOIS data retrieved for {domain}"

    results.append(ScanResult(
        module="recon-whois",
        target=domain,
        port=43,
        status="found",
        severity=Severity.INFO,
        detail=detail,
        data=parsed,
        confidence=Confidence.CERTAIN,
    ))

    if parsed.get("expiration_date"):
        exp = _parse_date(parsed["expiration_date"])
        if exp:
            now = datetime.now(timezone.utc)
            days_left = (exp - now).days
            if days_left <= 30:
                results.append(ScanResult(
                    module="recon-whois",
                    target=domain,
                    port=43,
                    status="expiring",
                    severity=Severity.HIGH,
                    detail=f"Domain expires in {days_left} day(s) — potential domain hijack risk",
                    data={"expiration_date": parsed["expiration_date"], "days_left": days_left},
                    confidence=Confidence.CERTAIN,
                ))

    dnssec_val = (parsed.get("dnssec") or "").lower()
    if dnssec_val and "unsigned" in dnssec_val:
        results.append(ScanResult(
            module="recon-whois",
            target=domain,
            port=43,
            status="dnssec-unsigned",
            severity=Severity.MEDIUM,
            detail="DNSSEC is not enabled — DNS responses can be spoofed",
            data={"dnssec": parsed.get("dnssec", "")},
            confidence=Confidence.FIRM,
        ))
    elif not dnssec_val:
        results.append(ScanResult(
            module="recon-whois",
            target=domain,
            port=43,
            status="dnssec-unknown",
            severity=Severity.MEDIUM,
            detail="DNSSEC status unknown — likely not enabled",
            data={"dnssec": ""},
            confidence=Confidence.TENTATIVE,
        ))

    if _is_privacy_proxy(raw):
        results.append(ScanResult(
            module="recon-whois",
            target=domain,
            port=43,
            status="privacy-proxy",
            severity=Severity.INFO,
            detail="Domain uses privacy/proxy registration — registrant details are redacted",
            data={"privacy_proxy": True},
            confidence=Confidence.FIRM,
        ))

    return results

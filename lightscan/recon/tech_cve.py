"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations

import asyncio
import re

from lightscan.core.models import Confidence, ScanResult, Severity

KNOWN_VULNS: dict[str, list[dict]] = {
    "apache": [
        {"range": "<=2.4.49", "cve": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Path traversal and RCE via mod_cgi"},
        {"range": "<=2.4.50", "cve": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Path traversal bypass of CVE-2021-41773 fix"},
        {"range": "<=2.4.51", "cve": "CVE-2022-22720", "severity": "HIGH", "desc": "HTTP request smuggling"},
    ],
    "nginx": [
        {"range": "<=1.20.0", "cve": "CVE-2021-23017", "severity": "HIGH", "desc": "DNS resolver off-by-one heap write"},
    ],
    "php": [
        {"range": "<=8.1.0-dev", "cve": "CVE-2021-21708", "severity": "CRITICAL", "desc": "RCE via backdoor in PHP source"},
        {"range": "<=7.4.21", "cve": "CVE-2021-21703", "severity": "HIGH", "desc": "FPM root privilege escalation"},
    ],
    "openssh": [
        {"range": "<=8.9", "cve": "CVE-2023-38408", "severity": "HIGH", "desc": "PKCS#11 remote code execution via forwarded agent"},
        {"range": "<=9.7", "cve": "CVE-2024-6387", "severity": "CRITICAL", "desc": "regreSSHion: Remote unauthenticated RCE"},
    ],
    "openssl": [
        {"range": "<=3.0.6", "cve": "CVE-2022-3602", "severity": "HIGH", "desc": "X.509 buffer overread"},
    ],
    "jquery": [
        {"range": "<=3.4.1", "cve": "CVE-2020-11022", "severity": "MEDIUM", "desc": "XSS via htmlPrefilter"},
    ],
    "wordpress": [
        {"range": "<=5.8.3", "cve": "CVE-2022-21661", "severity": "HIGH", "desc": "SQL injection via WP_Query"},
    ],
    "iis": [
        {"range": "<=10.0", "cve": "CVE-2021-31166", "severity": "CRITICAL", "desc": "HTTP Protocol Stack RCE"},
    ],
    "tomcat": [
        {"range": "<=9.0.43", "cve": "CVE-2021-25329", "severity": "HIGH", "desc": "RCE via session persistence"},
        {"range": "<=10.1.0-M1", "cve": "CVE-2024-50379", "severity": "CRITICAL", "desc": "RCE via partial PUT on case-insensitive FS"},
    ],
}

_VERSION_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9_\-]*)[/\s]+([\d]+(?:\.[\d]+)*(?:[\-.][\w]+)*)")

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    cleaned = re.split(r"[-_+]", version_str)[0]
    parts = []
    for p in cleaned.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


def _version_lte(detected: str, upper_bound: str) -> bool:
    det = _parse_version_tuple(detected)
    bound = _parse_version_tuple(upper_bound)

    max_len = max(len(det), len(bound))
    det_padded = det + (0,) * (max_len - len(det))
    bound_padded = bound + (0,) * (max_len - len(bound))

    return det_padded <= bound_padded


def _extract_tech(tech_dict: dict) -> list[tuple[str, str]]:
    technologies: list[tuple[str, str]] = []
    for key, value in tech_dict.items():
        if not isinstance(value, str):
            continue
        for match in _VERSION_RE.finditer(value):
            product = match.group(1).lower()
            version = match.group(2)
            technologies.append((product, version))
        value_lower = value.lower()
        if "microsoft-iis" in value_lower or "iis" in value_lower:
            m = re.search(r"(\d+(?:\.\d+)*)", value)
            if m and ("iis", m.group(1)) not in technologies:
                technologies.append(("iis", m.group(1)))
    return technologies


def _correlate(tech_list: list[tuple[str, str]]) -> list[dict]:
    matches: list[dict] = []
    seen_cves: set[str] = set()

    for product, version in tech_list:
        vulns = KNOWN_VULNS.get(product, [])
        for vuln in vulns:
            range_str = vuln["range"]
            if range_str.startswith("<="):
                upper = range_str[2:]
            else:
                upper = range_str
            if _version_lte(version, upper):
                cve = vuln["cve"]
                if cve not in seen_cves:
                    seen_cves.add(cve)
                    matches.append({
                        "cve": cve,
                        "product": product,
                        "detected_version": version,
                        "vulnerable_range": vuln["range"],
                        "severity": vuln["severity"],
                        "description": vuln["desc"],
                    })
    return matches


async def tech_cve_correlate_async(
    tech_dict: dict,
    timeout: float = 10.0,
) -> list[ScanResult]:
    if not tech_dict:
        return []

    results: list[ScanResult] = []
    try:
        tech_list = _extract_tech(tech_dict)
        matches = await asyncio.to_thread(_correlate, tech_list)
    except Exception:
        return results

    for match in matches:
        cve_id = match["cve"]
        severity = _SEVERITY_MAP.get(match["severity"], Severity.INFO)
        results.append(ScanResult(
            module=f"recon-cve-{cve_id.lower()}",
            target="",
            port=0,
            status="vulnerable",
            severity=severity,
            detail=(
                f"{match['product']}/{match['detected_version']} — "
                f"{cve_id}: {match['description']}"
            ),
            data=match,
            confidence=Confidence.FIRM,
        ))

    return results

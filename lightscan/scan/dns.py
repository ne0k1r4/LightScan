# scan/dns.py — v0.6 basic DNS enumeration
# Light (Neok1ra)
from __future__ import annotations
import asyncio
import socket
from lightscan.core.engine import ScanResult, Severity


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
    "vpn", "remote", "dev", "staging", "api", "admin",
    "portal", "git", "gitlab", "jenkins", "jira", "confluence",
]


async def _resolve(sub: str, domain: str) -> str | None:
    host = f"{sub}.{domain}"
    try:
        loop = asyncio.get_running_loop()
        ip   = await loop.run_in_executor(None, socket.gethostbyname, host)
        return f"{host} → {ip}"
    except Exception:
        return None


async def full_dns_enum(domain: str, axfr: bool = True,
                        timeout: float = 5.0) -> list[ScanResult]:
    results = []

    # subdomain bruteforce
    tasks   = [_resolve(s, domain) for s in COMMON_SUBDOMAINS]
    found   = await asyncio.gather(*tasks)
    for f in found:
        if f:
            results.append(ScanResult("dns", domain, 53, "DNS",
                Severity.INFO, f))

    return results

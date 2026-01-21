# scan/portscan.py — TCP connect + banner grab v0.2
# Light
from __future__ import annotations
import asyncio
import socket
from lightscan.core.engine import ScanResult, Severity

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
}


async def _grab_banner(host, port, timeout=2.0) -> str:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            banner = await asyncio.wait_for(r.read(256), timeout=timeout)
            w.close()
            return banner.decode("utf-8", "replace").strip()
        except Exception:
            w.close()
            return ""
    except Exception:
        return ""


async def scan_port(host: str, port: int, timeout: float) -> ScanResult | None:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.close()
    except Exception:
        return None

    service = SERVICE_MAP.get(port, f"port/{port}")
    banner  = await _grab_banner(host, port, timeout)
    detail  = f"{service} | {banner}" if banner else service
    sev     = Severity.INFO
    if port in (21, 23, 445, 3389):
        sev = Severity.HIGH
    return ScanResult("scan", host, port, service, sev, detail)


def build_scan_tasks(hosts, ports, timeout, udp=False):
    tasks = []
    for host in hosts:
        for port in ports:
            tasks.append((scan_port(host, port, timeout), f"{host}:{port}"))
    return tasks

# scan/udp.py — v0.6 basic UDP scanner
# Light
from __future__ import annotations
import asyncio
import socket
from lightscan.core.engine import ScanResult, Severity

UDP_PROBES = {
    53:  b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",  # DNS
    161: b"\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63",  # SNMP
    123: b"\x1b" + b"\x00" * 47,  # NTP
}


async def udp_scan(host: str, port: int, timeout: float = 2.0) -> ScanResult | None:
    probe = UDP_PROBES.get(port, b"\x00" * 4)
    try:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        await loop.run_in_executor(None, sock.sendto, probe, (host, port))
        data, _ = await asyncio.wait_for(
            loop.run_in_executor(None, sock.recvfrom, 256), timeout=timeout)
        sock.close()
        if data:
            return ScanResult("udp", host, port, f"UDP/{port}",
                Severity.INFO, f"response: {len(data)} bytes")
    except Exception:
        pass
    return None

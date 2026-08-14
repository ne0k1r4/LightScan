"""Protocol-aware service version detection for confirmed TCP services."""
from __future__ import annotations

import asyncio
import re
import struct

from lightscan.core.engine import ScanResult, Severity

DEFAULT_TIMEOUT = 3.0


async def _probe(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        if payload:
            writer.write(payload)
            await writer.drain()
        return await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return b""
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def _banner(host: str, port: int, timeout: float) -> bytes:
    return await _probe(host, port, b"", timeout)


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace").strip()


async def probe_ssh(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    text = _text(await _banner(host, port, timeout))
    match = re.match(r"SSH-([\d.]+)-(.+?)(?:\s|$)", text)
    if not match:
        return {}
    return {
        "service": "SSH",
        "version": match.group(2).strip(),
        "protocol": f"SSH-{match.group(1)}",
        "raw": text[:120],
    }


async def probe_http(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    payload = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: LightScan/2\r\n\r\n".encode()
    text = _text(await _probe(host, port, payload, timeout))
    match = re.search(r"Server:\s*(.+?)(?:\r|\n)", text, re.IGNORECASE)
    if not match:
        return {}
    return {"service": "HTTP", "version": match.group(1).strip(), "raw": text[:200]}


async def probe_https(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    import ssl

    writer = None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout,
        )
        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        await writer.drain()
        text = _text(await asyncio.wait_for(reader.read(4096), timeout=timeout))
        match = re.search(r"Server:\s*(.+?)(?:\r|\n)", text, re.IGNORECASE)
        if not match:
            return {}
        return {"service": "HTTPS", "version": match.group(1).strip(), "raw": text[:200]}
    except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError):
        return {}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def probe_ftp(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    text = _text(await _banner(host, port, timeout))
    match = re.match(r"220[- ](.+)", text)
    return {"service": "FTP", "version": match.group(1).strip()[:80]} if match else {}


async def probe_smtp(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    text = _text(await _banner(host, port, timeout))
    if not text.startswith("220"):
        return {}
    result = {"service": "SMTP", "version": text[4:80].strip()}
    capabilities = _text(await _probe(host, port, b"EHLO lightscan.local\r\n", timeout))
    advertised = re.findall(r"250[- ](.+?)(?:\r|\n)", capabilities)
    if advertised:
        result["capabilities"] = advertised[:10]
    return result


async def probe_pop3(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    text = _text(await _banner(host, port, timeout))
    return {"service": "POP3", "version": text[4:80].strip()} if text.startswith("+OK") else {}


async def probe_imap(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    text = _text(await _banner(host, port, timeout))
    if "OK" not in text[:10]:
        return {}
    product = re.search(r"Dovecot|Courier|Cyrus|Exchange", text, re.IGNORECASE)
    return {"service": "IMAP", "version": (product.group(0) if product else text[5:60]).strip()}


async def probe_mysql(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    data = await _banner(host, port, timeout)
    if len(data) < 5:
        return {}
    if data[4] == 0x0A:
        try:
            end = data.index(b"\x00", 5)
            return {"service": "MySQL", "version": data[5:end].decode("utf-8", "replace")}
        except ValueError:
            return {}
    if data[4] == 0xFF:
        return {"service": "MySQL", "version": "unknown (authentication error)"}
    return {}


async def probe_redis(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    text = _text(await _probe(host, port, b"INFO server\r\n", timeout))
    match = re.search(r"redis_version:(.+?)(?:\r|\n)", text)
    if match:
        return {"service": "Redis", "version": match.group(1).strip()}
    response = await _probe(host, port, b"PING\r\n", timeout)
    if b"+PONG" in response or b"-NOAUTH" in response:
        return {"service": "Redis", "version": "authentication required"}
    return {}


async def probe_postgres(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    startup = struct.pack(">II", 0, 196608) + b"user\x00lightscan\x00\x00"
    payload = struct.pack(">I", len(startup) + 4) + startup[4:]
    data = await _probe(host, port, payload, timeout)
    if not data or data[0:1] not in (b"R", b"E", b"N"):
        return {}
    match = re.search(r"PostgreSQL ([\d.]+)", _text(data))
    return {"service": "PostgreSQL", "version": match.group(1) if match else "detected"}


async def probe_rdp(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    request = bytes([0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00])
    data = await _probe(host, port, request, timeout)
    return {"service": "RDP", "version": "detected"} if data[:1] == b"\x03" else {}


async def probe_memcached(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    text = _text(await _probe(host, port, b"version\r\n", timeout))
    match = re.match(r"VERSION (.+)", text)
    return {"service": "Memcached", "version": match.group(1).strip()} if match else {}


async def probe_telnet(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    data = await _banner(host, port, timeout)
    if not data:
        return {}
    text = re.sub(r"\xff..", "", _text(data)).strip()
    return {"service": "Telnet", "version": text[:80] or "binary negotiation"}


PROBE_MAP: dict[int, list] = {
    21: [probe_ftp], 22: [probe_ssh], 23: [probe_telnet], 25: [probe_smtp],
    80: [probe_http], 110: [probe_pop3], 143: [probe_imap],
    443: [probe_https], 465: [probe_smtp], 587: [probe_smtp],
    993: [probe_imap], 995: [probe_pop3], 3306: [probe_mysql],
    3389: [probe_rdp], 5432: [probe_postgres], 6379: [probe_redis],
    8080: [probe_http], 8443: [probe_https], 11211: [probe_memcached],
}
GENERIC_PROBES = [probe_ftp, probe_smtp, probe_ssh, probe_http]


async def detect_version(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Identify one confirmed open service using the smallest relevant probe set."""
    for probe in PROBE_MAP.get(port, GENERIC_PROBES):
        result = await probe(host, port, timeout)
        if result:
            return result
    return {}


async def detect_versions_bulk(
    host: str,
    ports: list[int],
    concurrency: int = 20,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[int, dict]:
    """Probe confirmed open ports concurrently while retaining their port mapping."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results: dict[int, dict] = {}

    async def probe_one(port: int) -> None:
        async with semaphore:
            info = await detect_version(host, port, timeout)
            if info:
                results[port] = info

    await asyncio.gather(*(probe_one(port) for port in ports))
    return results


async def detect_services(
    host: str,
    ports: list[int],
    timeout: float = DEFAULT_TIMEOUT,
    *,
    concurrency: int = 20,
    verbose: bool = False,
) -> list[ScanResult]:
    """Return probe-derived service results in LightScan's common result model."""
    del verbose  # Retained for compatibility with existing CLI callers.
    findings: list[ScanResult] = []
    detected = await detect_versions_bulk(host, ports, concurrency=concurrency, timeout=timeout)
    for port, info in sorted(detected.items()):
        service = info.get("service", "unknown")
        version = info.get("version", "").strip()
        detail = f"{service} {version}".strip()
        data = {"method": "probed", "confidence": 10, **info}
        findings.append(
            ScanResult(
                "service-version",
                host,
                port,
                "open",
                Severity.INFO,
                detail,
                data,
            )
        )
    return findings

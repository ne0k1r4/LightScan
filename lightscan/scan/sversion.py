# scan/sversion.py — nmap-style protocol probe matching
# Light (Neok1ra)
#
# sends actual protocol probes, not just reads first 256 bytes.
# SSH: parse version string  HTTP: HEAD + Server header
# FTP: 220 banner            SMTP: 220 + EHLO capabilities
# MySQL: greeting packet     Redis: INFO server command
# Postgres: startup msg      MongoDB: wire protocol hello
# Memcached: version cmd     RDP: X.224 connection request
from __future__ import annotations
import asyncio, re, struct

_T = 3.0


async def _probe(host: str, port: int, payload: bytes, timeout: float = _T) -> bytes:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        if payload: w.write(payload); await w.drain()
        data = await asyncio.wait_for(r.read(4096), timeout=timeout)
        w.close()
        return data
    except Exception:
        return b""


async def _banner(host, port, timeout=_T): return await _probe(host, port, b"", timeout)
def _s(b): return b.decode("utf-8", "replace").strip()


async def probe_ssh(host, port):
    t = _s(await _banner(host, port))
    m = re.match(r"SSH-([\d.]+)-(.+?)(?:\s|$)", t)
    return {"service": "SSH", "version": m.group(2).strip(), "proto": f"SSH-{m.group(1)}", "raw": t[:120]} if m else {}

async def probe_http(host, port):
    d = await _probe(host, port, f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode())
    t = _s(d)
    r = {"service": "HTTP"}
    m = re.search(r"Server:\s*(.+?)(?:\r|\n)", t, re.I)
    if m: r["version"] = m.group(1).strip()
    return r if r.get("version") else {}

async def probe_https(host, port):
    try:
        import ssl
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=_T)
        w.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()); await w.drain()
        d = await asyncio.wait_for(r.read(4096), timeout=_T); w.close()
        t = _s(d); m = re.search(r"Server:\s*(.+?)(?:\r|\n)", t, re.I)
        return {"service": "HTTPS", "version": m.group(1).strip()} if m else {}
    except Exception: return {}

async def probe_ftp(host, port):
    t = _s(await _banner(host, port))
    m = re.match(r"220[- ](.+)", t)
    return {"service": "FTP", "version": m.group(1).strip()[:80]} if m else {}

async def probe_smtp(host, port):
    t = _s(await _banner(host, port))
    if not t.startswith("220"): return {}
    r = {"service": "SMTP", "version": t[4:80].strip()}
    eh = _s(await _probe(host, port, b"EHLO lightscan.local\r\n"))
    caps = re.findall(r"250[- ](.+?)(?:\r|\n)", eh)
    if caps: r["capabilities"] = caps[:10]
    return r

async def probe_pop3(host, port):
    t = _s(await _banner(host, port))
    return {"service": "POP3", "version": t[4:80].strip()} if t.startswith("+OK") else {}

async def probe_imap(host, port):
    t = _s(await _banner(host, port))
    if "OK" not in t[:10]: return {}
    m = re.search(r"Dovecot|Courier|Cyrus|Exchange", t, re.I)
    return {"service": "IMAP", "version": (m.group(0) if m else t[5:60]).strip()}

async def probe_mysql(host, port):
    d = await _banner(host, port)
    if len(d) < 5: return {}
    if d[4] == 0x0a:
        try:
            end = d.index(b"\x00", 5)
            return {"service": "MySQL", "version": d[5:end].decode("utf-8","replace")}
        except Exception: pass
    if d[4] == 0xff: return {"service": "MySQL", "version": "unknown (auth error)"}
    return {}

async def probe_redis(host, port):
    d = await _probe(host, port, b"INFO server\r\n")
    t = _s(d)
    m = re.search(r"redis_version:(.+?)(?:\r|\n)", t)
    if m: return {"service": "Redis", "version": m.group(1).strip()}
    ping = await _probe(host, port, b"PING\r\n")
    if b"+PONG" in ping or b"-NOAUTH" in ping:
        return {"service": "Redis", "version": "auth required"}
    return {}

async def probe_postgres(host, port):
    msg = struct.pack(">II", 0, 196608) + b"user\x00lightscan\x00\x00"
    msg = struct.pack(">I", len(msg)+4) + msg[4:]
    d = await _probe(host, port, msg)
    if not d: return {}
    if d[0:1] in (b"R", b"E", b"N"):
        m = re.search(r"PostgreSQL ([\d.]+)", _s(d))
        return {"service": "PostgreSQL", "version": m.group(1) if m else "detected"}
    return {}

async def probe_rdp(host, port):
    rdp = bytes([0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00])
    d = await _probe(host, port, rdp)
    return {"service": "RDP", "version": "detected"} if d and d[0] == 0x03 else {}

async def probe_memcached(host, port):
    t = _s(await _probe(host, port, b"version\r\n"))
    m = re.match(r"VERSION (.+)", t)
    return {"service": "Memcached", "version": m.group(1).strip()} if m else {}

async def probe_telnet(host, port):
    d = await _banner(host, port)
    if not d: return {}
    import re as _re
    text = _re.sub(r'\xff..', '', _s(d)).strip()
    return {"service": "Telnet", "version": text[:80]} if text else {"service": "Telnet", "version": "binary negotiation"}

PROBE_MAP: dict[int, list] = {
    21: [probe_ftp], 22: [probe_ssh], 23: [probe_telnet], 25: [probe_smtp],
    80: [probe_http], 110: [probe_pop3], 143: [probe_imap],
    443: [probe_https], 465: [probe_smtp], 587: [probe_smtp],
    993: [probe_imap], 995: [probe_pop3], 3306: [probe_mysql],
    3389: [probe_rdp], 5432: [probe_postgres], 6379: [probe_redis],
    8080: [probe_http], 8443: [probe_https], 11211: [probe_memcached],
}
GENERIC = [probe_ftp, probe_smtp, probe_ssh, probe_http]


async def detect_version(host: str, port: int, timeout: float = _T) -> dict:
    for fn in PROBE_MAP.get(port, GENERIC):
        try:
            r = await asyncio.wait_for(fn(host, port), timeout=timeout)
            if r: return r
        except Exception: continue
    return {}


async def detect_versions_bulk(host: str, ports: list[int],
                                concurrency: int = 20, timeout: float = _T) -> dict[int, dict]:
    sem = asyncio.Semaphore(concurrency)
    results: dict[int, dict] = {}
    async def _one(p):
        async with sem:
            info = await detect_version(host, p, timeout)
            if info: results[p] = info
    await asyncio.gather(*[_one(p) for p in ports])
    return results

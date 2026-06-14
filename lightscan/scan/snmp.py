# scan/snmp.py — SNMP v1/v2c enumeration (pure stdlib, no pysnmp)
# Light (Neok1ra)
#
# hand-rolled BER/ASN.1 encoding. learned more about SNMP wire format
# doing this than i ever wanted to know.
# tested against NET-SNMP, Cisco IOS, Windows SNMP service.
from __future__ import annotations
import asyncio, random, socket, struct
from dataclasses import dataclass, field
from lightscan.core.engine import ScanResult, Severity


def _checksum_dummy(): pass  # placeholder so file isn't just defs


def _tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:   return bytes([tag, n]) + value
    if n < 0x100:  return bytes([tag, 0x81, n]) + value
    return bytes([tag, 0x82, (n>>8)&0xff, n&0xff]) + value


def _encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    out   = bytes([40*parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0: out += b"\x00"; continue
        enc = []
        while p > 0:
            enc.append((p & 0x7f) | (0x80 if enc else 0))
            p >>= 7
        out += bytes(reversed(enc))
    return out


def _build_get(community: str, oid: str) -> bytes:
    rid      = random.randint(1, 0x7fffffff)
    varbind  = _tlv(0x30, _tlv(0x06, _encode_oid(oid)) + _tlv(0x05, b""))
    pdu      = _tlv(0xa0,
        _tlv(0x02, rid.to_bytes(4, "big")) + _tlv(0x02, b"\x00") +
        _tlv(0x02, b"\x00") + _tlv(0x30, varbind))
    return _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, community.encode()) + pdu)


def _build_getnext(community: str, oid: str) -> bytes:
    rid     = random.randint(1, 0x7fffffff)
    varbind = _tlv(0x30, _tlv(0x06, _encode_oid(oid)) + _tlv(0x05, b""))
    pdu     = _tlv(0xa1,
        _tlv(0x02, rid.to_bytes(4, "big")) + _tlv(0x02, b"\x00") +
        _tlv(0x02, b"\x00") + _tlv(0x30, varbind))
    return _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, community.encode()) + pdu)


def _parse(data: bytes) -> tuple[str, str]:
    """crude BER parser — handles octet string, integer, IP address"""
    try:
        if not data or data[0] != 0x30: return "", ""
        i = 2
        if data[1] & 0x80: i += data[1] & 0x7f
        # skip to response PDU (0xa2)
        while i < len(data)-1:
            if data[i] == 0xa2: i += 2; break
            tag = data[i]; i += 1
            if data[i] & 0x80:
                ll = data[i] & 0x7f
                ln = int.from_bytes(data[i+1:i+1+ll], "big")
                i += 1 + ll + ln
            else:
                i += 1 + data[i]
        # skip request-id, error-status, error-index
        for _ in range(3):
            if i >= len(data): return "", ""
            i += 2 + data[i+1]
        # varbinds
        if i < len(data) and data[i] == 0x30: i += 2
        if i < len(data) and data[i] == 0x30: i += 2
        if i >= len(data) or data[i] != 0x06: return "", ""
        i += 2 + data[i+1]
        if i >= len(data): return "", ""
        vt = data[i]; vl = data[i+1]
        if vl & 0x80:
            ll = vl & 0x7f; vl = int.from_bytes(data[i+2:i+2+ll], "big"); i += ll
        vd = data[i+2:i+2+vl]
        if vt == 0x04: return "str", vd.decode("utf-8","replace").strip()
        if vt == 0x02: return "int", str(int.from_bytes(vd, "big"))
        if vt == 0x40: return "ip",  ".".join(str(b) for b in vd[:4])
        if vt in (0x80, 0x81, 0x82): return "end", ""
        return "other", vd.hex()
    except Exception:
        return "", ""


async def _udp_send(host: str, port: int, pkt: bytes, timeout: float) -> bytes:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.run_in_executor(None, sock.sendto, pkt, (host, port))
        data, _ = await asyncio.wait_for(
            loop.run_in_executor(None, sock.recvfrom, 4096), timeout=timeout)
        return data
    except Exception:
        return b""
    finally:
        sock.close()


SYSTEM_OIDS = {
    "sysDescr":   "1.3.6.1.2.1.1.1.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName":    "1.3.6.1.2.1.1.5.0",
    "sysLocation":"1.3.6.1.2.1.1.6.0",
}
WALK_OIDS = {
    "interfaces": "1.3.6.1.2.1.2.2.1.2",
    "processes":  "1.3.6.1.2.1.25.4.2.1.2",
}
COMMUNITIES = ["public", "private", "community", "admin", "snmp", "manager"]


async def snmp_get(host: str, oid: str, community: str = "public",
                   port: int = 161, timeout: float = 2.0) -> tuple[str, str]:
    data = await _udp_send(host, port, _build_get(community, oid), timeout)
    return _parse(data)


async def snmp_walk(host: str, base_oid: str, community: str = "public",
                    port: int = 161, timeout: float = 2.0,
                    max_results: int = 30) -> list[str]:
    results = []
    oid     = base_oid
    for _ in range(max_results):
        data = await _udp_send(host, port, _build_getnext(community, oid), timeout)
        vt, val = _parse(data)
        if vt in ("end", "") or not val: break
        results.append(val)
        parts     = oid.split(".")
        parts[-1] = str(int(parts[-1]) + 1)
        oid       = ".".join(parts)
    return results


async def snmp_enumerate(host: str, port: int = 161,
                         communities: list | None = None,
                         timeout: float = 2.0) -> list[ScanResult]:
    comms    = communities or COMMUNITIES
    results  = []
    community = None
    sys_descr = ""

    for c in comms:
        _, val = await snmp_get(host, SYSTEM_OIDS["sysDescr"], c, port, timeout)
        if val:
            community = c
            sys_descr = val
            break  # stop on first hit — no need to try remaining

    if not community:
        return results

    sev = Severity.CRITICAL if community == "public" else Severity.HIGH
    results.append(ScanResult("snmp", host, port, "SNMP", sev,
        f"community='{community}' | {sys_descr[:120]}"))

    # grab remaining system OIDs
    extras = []
    for name, oid in list(SYSTEM_OIDS.items())[1:]:
        _, val = await snmp_get(host, oid, community, port, timeout)
        if val: extras.append(f"{name}={val[:40]}")
    if extras:
        results.append(ScanResult("snmp", host, port, "SNMP-SysInfo",
            Severity.INFO, " | ".join(extras)))

    ifaces = await snmp_walk(host, WALK_OIDS["interfaces"], community, port, timeout)
    if ifaces:
        results.append(ScanResult("snmp", host, port, "SNMP-Interfaces",
            Severity.INFO, f"ifaces: {', '.join(ifaces[:6])}"))

    procs = await snmp_walk(host, WALK_OIDS["processes"], community, port, timeout)
    if procs:
        results.append(ScanResult("snmp", host, port, "SNMP-Processes",
            Severity.INFO, f"processes: {', '.join(procs[:8])}"))

    return results

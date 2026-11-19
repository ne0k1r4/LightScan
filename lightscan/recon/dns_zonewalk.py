"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations

import asyncio
import socket
import struct
import time

from lightscan.core.models import Confidence, ScanResult, Severity

NSEC_TYPE = 47
NSEC3PARAM_TYPE = 51
MAX_WALK_ITERATIONS = 500


def _build_query(qname: str, qtype: int = 1) -> bytes:
    txid = int(time.time() * 1000) & 0xFFFF
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = b""
    for part in qname.split("."):
        enc = part.encode()
        labels += struct.pack("B", len(enc)) + enc
    return hdr + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    pos = offset
    jumped = False
    orig_pos = pos
    max_jumps = 20
    jump_count = 0
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                break
            ptr = struct.unpack("!H", data[pos:pos + 2])[0] & 0x3FFF
            if not jumped:
                orig_pos = pos + 2
            jumped = True
            pos = ptr
            jump_count += 1
            if jump_count > max_jumps:
                break
            continue
        pos += 1
        if pos + length > len(data):
            break
        labels.append(data[pos:pos + length].decode("utf-8", "replace"))
        pos += length
    name = ".".join(labels)
    return name, orig_pos if jumped else pos


def _parse_nsec_response(data: bytes) -> list[str]:
    names: list[str] = []
    if len(data) < 12:
        return names
    ancount = struct.unpack("!H", data[6:8])[0]
    nscount = struct.unpack("!H", data[8:10])[0]
    arcount = struct.unpack("!H", data[10:12])[0]

    pos = 12
    _, pos = _decode_name(data, pos)
    pos += 4

    total_rr = ancount + nscount + arcount
    for _ in range(min(total_rr, 50)):
        if pos >= len(data):
            break
        _, pos = _decode_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == NSEC_TYPE and rdlen > 0:
            next_name, _ = _decode_name(data, pos)
            if next_name:
                names.append(next_name.rstrip(".").lower())
        pos += rdlen
    return names


def _check_nsec3param(data: bytes) -> bool:
    if len(data) < 12:
        return False
    ancount = struct.unpack("!H", data[6:8])[0]
    nscount = struct.unpack("!H", data[8:10])[0]
    arcount = struct.unpack("!H", data[10:12])[0]

    pos = 12
    _, pos = _decode_name(data, pos)
    pos += 4

    total_rr = ancount + nscount + arcount
    for _ in range(min(total_rr, 50)):
        if pos >= len(data):
            break
        _, pos = _decode_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == NSEC3PARAM_TYPE:
            return True
        pos += rdlen
    return False


def _udp_query(qname: str, qtype: int, nameserver: str, timeout: float) -> bytes:
    try:
        pkt = _build_query(qname, qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return data
    except Exception:
        return b""


def _blocking_zonewalk(
    domain: str,
    nameserver: str,
    timeout: float,
) -> tuple[list[str], bool, bool]:
    nsec3param_data = _udp_query(domain, NSEC3PARAM_TYPE, nameserver, timeout)
    has_nsec3 = _check_nsec3param(nsec3param_data) if nsec3param_data else False

    if has_nsec3:
        return [], True, False

    discovered: list[str] = []
    seen: set[str] = set()
    current = domain.lower()
    iterations = 0

    while iterations < MAX_WALK_ITERATIONS:
        iterations += 1
        data = _udp_query(current, NSEC_TYPE, nameserver, timeout)
        if not data:
            break

        next_names = _parse_nsec_response(data)
        if not next_names:
            break

        new_found = False
        for name in next_names:
            if name and name not in seen and name.endswith(domain.lower()):
                seen.add(name)
                discovered.append(name)
                new_found = True
                current = name

        if not new_found:
            break

        if current == domain.lower():
            break

    return discovered, False, len(discovered) > 0


async def dns_zonewalk_async(
    domain: str,
    nameserver: str = "8.8.8.8",
    timeout: float = 5.0,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    try:
        discovered, has_nsec3, success = await asyncio.to_thread(
            _blocking_zonewalk, domain, nameserver, timeout,
        )
    except Exception:
        return results

    if has_nsec3:
        results.append(ScanResult(
            module="recon-zonewalk",
            target=domain,
            port=53,
            status="nsec3-protected",
            severity=Severity.INFO,
            detail=f"Zone uses NSEC3 — zone walking is not feasible for {domain}",
            data={"nsec3": True, "domain": domain},
            confidence=Confidence.FIRM,
        ))
        return results

    if not success or not discovered:
        results.append(ScanResult(
            module="recon-zonewalk",
            target=domain,
            port=53,
            status="no-nsec",
            severity=Severity.INFO,
            detail=f"No NSEC records found for {domain} — zone walking not possible",
            data={"nsec": False, "domain": domain},
            confidence=Confidence.TENTATIVE,
        ))
        return results

    for name in discovered:
        results.append(ScanResult(
            module="recon-zonewalk",
            target=domain,
            port=53,
            status="discovered",
            severity=Severity.INFO,
            detail=f"Zone walk discovered: {name}",
            data={"hostname": name},
            confidence=Confidence.CERTAIN,
        ))

    results.append(ScanResult(
        module="recon-zonewalk",
        target=domain,
        port=53,
        status="zone-walkable",
        severity=Severity.LOW,
        detail=(
            f"DNS zone walking succeeded — {len(discovered)} hostname(s) enumerated. "
            f"Zone is not protected with NSEC3."
        ),
        data={"count": len(discovered), "hostnames": discovered},
        confidence=Confidence.CERTAIN,
    ))

    return results

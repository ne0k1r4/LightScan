# scan/discovery.py — host discovery before port scan
# Light (Neok1ra)
#
# two modes:
#   ARP sweep  — local subnet, fast, no firewall evasion needed
#   ICMP sweep — remote, needs root
#
# saves huge time on /24 scans with mostly dead hosts.
# wrote this after wasting 20 mins scanning a /24 where 200 hosts were down.
from __future__ import annotations
import asyncio
import ipaddress
import os
import socket
import struct
import time

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    scapy_conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


async def icmp_ping(host: str, timeout: float = 1.0) -> bool:
    """ICMP echo — requires root. falls back to TCP probe if no permission"""
    try:
        dst_ip = socket.gethostbyname(host)
        sock   = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        icmp_id  = os.getpid() & 0xffff
        header   = struct.pack("!BBHHH", 8, 0, 0, icmp_id, 1)
        payload  = b"lightscan"
        chk      = _checksum(header + payload)
        packet   = struct.pack("!BBHHH", 8, 0, chk, icmp_id, 1) + payload
        loop     = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, sock.sendto, packet, (dst_ip, 0))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data = await asyncio.wait_for(
                        loop.run_in_executor(None, sock.recv, 1024),
                        timeout=max(0.05, deadline - time.time()))
                    if len(data) >= 28:
                        icmp_hdr = data[20:]
                        r_type   = icmp_hdr[0]
                        r_id     = struct.unpack("!H", icmp_hdr[4:6])[0]
                        if r_type == 0 and r_id == icmp_id:
                            return True
                except (asyncio.TimeoutError, Exception):
                    break
        finally:
            sock.close()
    except PermissionError:
        return await _tcp_probe(host, timeout)
    except Exception:
        pass
    return False


async def _tcp_probe(host: str, timeout: float) -> bool:
    for port in (80, 443, 22, 8080):
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
            w.close()
            return True
        except Exception:
            continue
    return False


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s  = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def arp_sweep(network: str, timeout: float = 2.0) -> list[str]:
    if not HAS_SCAPY:
        return []
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                     timeout=timeout, verbose=False)
        return [rcv.psrc for _, rcv in ans]
    except Exception:
        return []


async def discover_hosts(targets: list[str], timeout: float = 1.0,
                         concurrency: int = 256, verbose: bool = False) -> list[str]:
    """run host discovery — single targets skip ping, subnets get swept"""
    if len(targets) == 1:
        return targets

    if verbose:
        print(f"[DISCOVER] pinging {len(targets)} hosts...")

    sem  = asyncio.Semaphore(concurrency)
    live = []
    done = 0

    async def _check(host):
        nonlocal done
        async with sem:
            up = await icmp_ping(host, timeout)
            done += 1
            if up:
                live.append(host)
            if verbose:
                print(f"\r[DISCOVER] {done}/{len(targets)}  up={len(live)}", end="", flush=True)

    await asyncio.gather(*[_check(h) for h in targets])
    if verbose:
        print()
    print(f"[DISCOVER] {len(live)}/{len(targets)} hosts responded")
    return sorted(live)

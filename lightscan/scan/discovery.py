

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import time
from typing import Optional

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    scapy_conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

def _checksum(data: bytes) -> int:
    """one's complement checksum — standard for ICMP/IP headers."""
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    s  = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def _build_icmp_echo(icmp_id: int, seq: int = 1) -> bytes:
    """build a valid ICMP echo request packet."""
    header  = struct.pack("!BBHHH", 8, 0, 0, icmp_id, seq)
    payload = b"ne0k1ra-lightscan"
    chk     = _checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, chk, icmp_id, seq) + payload

async def icmp_ping(host: str, timeout: float = 1.0) -> bool:
    """
    ICMP echo probe. Needs root or CAP_NET_RAW.
    Falls back to TCP connect if permission denied.
    Returns True if host is alive.
    """
    try:
        dst_ip   = socket.gethostbyname(host)
        icmp_id  = os.getpid() & 0xFFFF
        sock     = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        loop     = asyncio.get_running_loop()

        try:
            packet = _build_icmp_echo(icmp_id)
            await loop.run_in_executor(None, sock.sendto, packet, (dst_ip, 0))

            deadline = time.time() + timeout
            while time.time() < deadline:
                remaining = max(0.05, deadline - time.time())
                try:
                    data = await asyncio.wait_for(
                        loop.run_in_executor(None, sock.recv, 1024),
                        timeout=remaining,
                    )
                    if len(data) >= 28:
                        icmp_type = data[20]
                        recv_id   = struct.unpack("!H", data[24:26])[0]
                        if icmp_type == 0 and recv_id == icmp_id:
                            return True
                except (asyncio.TimeoutError, OSError):
                    break
        finally:
            sock.close()

    except PermissionError:
        return await _tcp_probe(host, timeout)
    except Exception:
        pass
    return False

async def _tcp_probe(host: str, timeout: float) -> bool:
    """
    TCP connect probe for non-root discovery.
    Tries common ports — if ANY responds, host is up.
    Not as reliable as ICMP but works without root.
    Limitation: hosts with ALL these ports firewalled look dead.
    """
    for port in (80, 443, 22, 8080, 445):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            continue
    return False

def arp_sweep(network: str, timeout: float = 2.0) -> list[str]:
    """
    Broadcast ARP who-has to entire subnet, collect replies.

    Advantages over ICMP on LAN:
      - L2 — can't be firewalled by iptables
      - Gets MAC addresses as a bonus
      - Zero false negatives on local subnet (host must reply)

    Requires: scapy + root/CAP_NET_PACKET_RAW
    Returns empty list if scapy unavailable (callers handle gracefully).
    """
    if not HAS_SCAPY:
        return []
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            timeout=timeout,
            verbose=False,
        )
        return [rcv.psrc for _, rcv in ans]
    except Exception:
        return []

async def discover_hosts(
    targets: list[str],
    timeout: float = 1.0,
    concurrency: int = 256,
    verbose: bool = False,
) -> list[str]:
    """
    Filter a host list down to live hosts before port scanning.

    Algorithm:
      - Single host: skip discovery (always assume alive — saves RTT)
      - Multiple hosts: ICMP sweep with semaphore-bounded concurrency
      - ARP used separately by caller if on LAN (call arp_sweep() first)

    Returns sorted list of live IPs.
    Performance: 256 concurrent pings → ~1s for a /24 on LAN.
    """
    if len(targets) <= 1:
        return targets

    if verbose:
        print(
            f"[DISCOVER] pinging {len(targets)} hosts "
            f"(timeout={timeout:.1f}s, concurrency={concurrency})"
        )

    sem  = asyncio.Semaphore(concurrency)
    live: list[str] = []
    done = 0

    async def _check(host: str) -> None:
        nonlocal done
        async with sem:
            up    = await icmp_ping(host, timeout)
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

def expand_targets(target: str) -> list[str]:
    """
    Expand a target string to a list of IPs.
    Handles: single IP, CIDR, hostname.
    CIDR /32 and /128 return single-element list (no broadcast skip).
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]
    except ValueError:
        return [target]

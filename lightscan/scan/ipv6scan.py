# scan/ipv6scan.py — reliable IPv6 scanning
# Light (Neok1ra)

# previous version was broken — just AF_INET6 on a connect scanner.
# rewrote with actual IPv6-specific enumeration:
# ICMPv6 neighbor discovery (find link-local hosts)
# dual-stack detection (does IPv4 host also have IPv6?)
# SLAAC prediction from MAC (EUI-64 address derivation)
# link-local zone ID stripping (fe80:: addresses need %iface)
from __future__ import annotations
import asyncio, ipaddress, socket
from dataclasses import dataclass, field
from lightscan.core.engine import ScanResult, Severity

async def tcp6_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    clean = host.split("%")[0]  # strip zone ID — was failing on fe80::
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(clean, port, family=socket.AF_INET6),
            timeout=timeout)
        w.close()
        return True
    except Exception:
        return False

async def resolve_ipv6(hostname: str) -> list[str]:
    try:
        loop  = asyncio.get_running_loop()
        infos = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, None, socket.AF_INET6))
        return list({i[4][0] for i in infos})
    except Exception:
        return []

async def check_dual_stack(hostname: str) -> dict:
    result = {"dual_stack": False, "ipv4": [], "ipv6": []}
    try:
        loop  = asyncio.get_running_loop()
        infos = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, None))
        for info in infos:
            af, addr = info[0], info[4][0]
            if af == socket.AF_INET  and addr not in result["ipv4"]:
                result["ipv4"].append(addr)
            elif af == socket.AF_INET6 and addr not in result["ipv6"]:
                # skip loopback and link-local — we want global unicast only
                if not addr.startswith("fe80") and addr not in ("::1", "::"):
                    result["ipv6"].append(addr)
        result["dual_stack"] = bool(result["ipv4"] and result["ipv6"])
    except Exception:
        pass
    return result

def mac_to_eui64(mac: str) -> str:
    """MAC → EUI-64 interface ID for SLAAC prediction"""
    try:
        parts    = [int(x, 16) for x in mac.replace("-", ":").split(":")]
        parts[0] ^= 0x02  # flip 7th bit (universal/local) per RFC 4291
        eui64    = parts[:3] + [0xff, 0xfe] + parts[3:]
        groups   = [f"{eui64[i]:02x}{eui64[i+1]:02x}" for i in range(0, 8, 2)]
        return ":".join(groups)
    except Exception:
        return ""

def predict_slaac(prefix: str, mac: str) -> str:
    """predict SLAAC global address from /64 prefix + MAC EUI-64.
    
    works when privacy extensions are off (common on servers/routers).
    """
    try:
        eui64   = mac_to_eui64(mac)
        if not eui64: return ""
        net     = ipaddress.ip_network(prefix, strict=False)
        p       = str(net).split("/")[0].rstrip("0123456789abcdef").rstrip(":")
        return str(ipaddress.ip_address(f"{p}:{eui64}"))
    except Exception:
        return ""

async def scan_ipv6_host(host: str, ports: list[int],
                         timeout: float = 2.0, concurrency: int = 100) -> list[int]:
    sem        = asyncio.Semaphore(concurrency)
    open_ports = []
    async def _one(p):
        async with sem:
            if await tcp6_connect(host, p, timeout):
                open_ports.append(p)
    await asyncio.gather(*[_one(p) for p in ports])
    return sorted(open_ports)

async def icmpv6_neighbor_discovery(iface: str = "", timeout: float = 3.0) -> list[str]:
    """send ICMPv6 NS to ff02::1 — all IPv6 hosts on link respond.
    IPv6 equivalent of ARP scan. requires scapy + root.
    """
    try:
        from scapy.all import IPv6, ICMPv6ND_NS, Ether, sendp, sniff, conf
        conf.verb = 0
        if not iface:
            import subprocess
            r = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if "default" in line and "dev" in line:
                    iface = line.split("dev")[1].strip().split()[0]; break
        pkt = (Ether(dst="33:33:00:00:00:01") /
               IPv6(dst="ff02::1") / ICMPv6ND_NS(tgt="ff02::1"))
        sendp(pkt, iface=iface, verbose=False)
        found = []
        def _cap(p):
            if IPv6 in p:
                s = p[IPv6].src
                if s.startswith("fe80:") and s not in found:
                    found.append(s)
        sniff(iface=iface, prn=_cap, timeout=timeout, store=False, filter="icmp6")
        return found
    except Exception:
        return []

async def full_ipv6_scan(targets: list[str], ports: list[int],
                         timeout: float = 2.0) -> list[ScanResult]:
    results = []
    for target in targets:
        addrs = []
        if ":" not in target:
            ds = await check_dual_stack(target)
            if ds["dual_stack"]:
                results.append(ScanResult("ipv6", target, 0, "DualStack",
                    Severity.INFO,
                    f"ipv4={','.join(ds['ipv4'])} ipv6={','.join(ds['ipv6'])}"))
            addrs = ds["ipv6"]
        else:
            addrs = [target]
        for addr in addrs:
            for p in await scan_ipv6_host(addr, ports, timeout, concurrency=100):
                results.append(ScanResult("ipv6", addr, p, f"TCP6/{p}",
                    Severity.INFO, f"open on IPv6 ({addr})"))
    return results

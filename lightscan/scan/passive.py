# scan/passive.py — passive network recon via traffic sniffing
# Light (Neok1ra)

# zero packets sent. sits on interface and observes:
# ARP     → IP/MAC mapping, new host detection, OUI fingerprinting
# DNS     → hostname ↔ IP mapping from responses
# mDNS    → .local service discovery
# DHCP    → hostname from option 12, MAC from chaddr
# NetBIOS → Windows hostname + domain from UDP/137

# requires scapy + root. works great on pentest engagements —
# you learn a surprising amount just by watching for 60 seconds.
# added after i spent time on a network that blocked all ICMP but was
# broadcasting everything over mDNS. silent recon FTW.
from __future__ import annotations
import time
from dataclasses import dataclass, field

try:
    from scapy.all import (
        ARP, DNS, BOOTP, DHCP, sniff,
        Ether, IP, UDP, conf as scapy_conf
    )
    scapy_conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

@dataclass
class PassiveHost:
    ip:           str
    mac:          str   = ""
    hostname:     str   = ""
    dhcp_name:    str   = ""
    netbios_name: str   = ""
    services:     list  = field(default_factory=list)
    os_hints:     list  = field(default_factory=list)
    first_seen:   float = field(default_factory=time.time)
    last_seen:    float = field(default_factory=time.time)

    def touch(self): self.last_seen = time.time()

    def summary(self) -> str:
        parts = [self.ip]
        if self.mac: parts.append(self.mac)
        name = self.hostname or self.dhcp_name or self.netbios_name
        if name: parts.append(f"({name})")
        if self.os_hints: parts.append(f"[{self.os_hints[0]}]")
        if self.services: parts.append(f"svcs={','.join(self.services[:3])}")
        return "  ".join(parts)

class PassiveSniffer:
    def __init__(self, iface: str = "", timeout: float = 60.0, verbose: bool = False):
        self.iface   = iface or self._default_iface()
        self.timeout = timeout
        self.verbose = verbose
        self.hosts:   dict[str, PassiveHost] = {}
        self.dns_map: dict[str, str]         = {}

    def _default_iface(self) -> str:
        try:
            import subprocess
            r = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "dev": return parts[i+1]
        except Exception:
            pass
        return "eth0"

    def _host(self, ip: str) -> PassiveHost:
        if ip not in self.hosts:
            self.hosts[ip] = PassiveHost(ip=ip)
            if self.verbose:
                print(f"\r[PASSIVE] new: {ip}          ")
        self.hosts[ip].touch()
        return self.hosts[ip]

    def _pkt(self, pkt):
        try:
            if ARP in pkt:
                arp = pkt[ARP]
                if arp.op in (1, 2) and arp.psrc != "0.0.0.0":
                    h = self._host(arp.psrc)
                    if not h.mac and arp.hwsrc != "00:00:00:00:00:00":
                        h.mac = arp.hwsrc
                        oui = arp.hwsrc[:8].upper()
                        if oui in ("00:50:56", "00:0C:29"): h.os_hints.append("VMware")
                        elif oui.startswith("DC:A6:32"):    h.os_hints.append("RPi")

            if DNS in pkt and pkt[DNS].qr == 1:
                dns = pkt[DNS]
                for i in range(dns.ancount):
                    try:
                        rr = dns.an[i]
                        if rr.type == 1:
                            name = rr.rrname.decode("utf-8", "replace").rstrip(".")
                            ip   = rr.rdata
                            self.dns_map[name] = ip
                            h = self._host(ip)
                            if not h.hostname: h.hostname = name
                    except Exception:
                        pass

            if UDP in pkt and IP in pkt and pkt[UDP].dport == 5353 and DNS in pkt:
                src = pkt[IP].src if IP in pkt else ""
                if src and pkt[DNS].qr == 1:
                    h = self._host(src)
                    for i in range(pkt[DNS].ancount):
                        try:
                            rr = pkt[DNS].an[i]
                            if rr.type == 12:
                                svc = rr.rdata.decode("utf-8", "replace")
                                if "_ssh._tcp" in svc and "ssh" not in h.services:
                                    h.services.append("ssh")
                                elif "_http" in svc and "http" not in h.services:
                                    h.services.append("http")
                        except Exception:
                            pass

            if DHCP in pkt and BOOTP in pkt:
                ip = pkt[BOOTP].yiaddr
                if ip and ip != "0.0.0.0":
                    h = self._host(ip)
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "hostname":
                            name = opt[1]
                            h.dhcp_name = name.decode("utf-8", "replace") if isinstance(name, bytes) else name

            if UDP in pkt and pkt[UDP].dport == 137 and IP in pkt:
                h = self._host(pkt[IP].src)
                if not h.os_hints:
                    h.os_hints.append("Windows (NetBIOS)")
                if "windows" not in h.services:
                    h.services.append("windows")
        except Exception:
            pass

    def run(self) -> dict[str, PassiveHost]:
        if not HAS_SCAPY:
            print("[PASSIVE] scapy not installed — pip install scapy")
            return {}
        print(f"[PASSIVE] sniffing {self.iface} for {self.timeout:.0f}s — zero packets sent")
        try:
            sniff(iface=self.iface, prn=self._pkt, timeout=self.timeout, store=False,
                  filter="arp or udp port 53 or udp port 5353 or udp port 67 or udp port 137")
        except PermissionError:
            print("[PASSIVE] need root or CAP_NET_RAW")
            return {}
        except Exception as e:
            print(f"[PASSIVE] error: {e}")
            return {}
        print(f"\n[PASSIVE] {len(self.hosts)} hosts observed")
        return self.hosts

    def print_summary(self):
        for ip, h in sorted(self.hosts.items()):
            print(f"  {h.summary()}")

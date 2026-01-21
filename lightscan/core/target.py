# core/target.py — target parsing
# Light
from __future__ import annotations
import ipaddress
import socket


TOP100 = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,
    993,995,1723,3306,3389,5900,8080,8443,8888,
    9090,9200,9300,27017,6379,5432,1521,1433,
]


def parse_targets(spec: str) -> list[str]:
    targets = []
    for s in spec.split(","):
        s = s.strip()
        try:
            net = ipaddress.ip_network(s, strict=False)
            targets.extend(str(h) for h in net.hosts())
        except ValueError:
            try:
                targets.append(socket.gethostbyname(s))
            except Exception:
                targets.append(s)
    return targets


def parse_ports(spec: str) -> list[int]:
    if spec in ("top100", "top20"):
        return TOP100
    ports = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b)+1))
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return ports

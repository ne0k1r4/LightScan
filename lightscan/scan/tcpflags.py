"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations
from typing import Optional, Tuple

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

_FLAG_MAP = (
    (TCP_CWR, 'CWR'), (TCP_ECE, 'ECE'), (TCP_URG, 'URG'), (TCP_ACK, 'ACK'),
    (TCP_PSH, 'PSH'), (TCP_RST, 'RST'), (TCP_SYN, 'SYN'), (TCP_FIN, 'FIN'),
)

def parse_tcp_flags(flags: int) -> dict:
    return {name: bool(flags & bit) for bit, name in _FLAG_MAP}

def flags_str(flags: int) -> str:
    active = [name for bit, name in _FLAG_MAP if flags & bit]
    return '|'.join(active) if active else 'NONE'

def classify_tcp(flags: int) -> Optional[str]:
    f = parse_tcp_flags(flags)
    if f['SYN'] and f['ACK'] and not f['RST'] and not f['FIN']:
        return 'open'
    if f['RST']:
        return 'closed'
    if f['FIN'] and f['ACK'] and not f['SYN'] and not f['RST']:
        return 'closed'
    return None

def is_firewall_rst(flags: int) -> bool:
    f = parse_tcp_flags(flags)
    return f['RST'] and not f['ACK']

ICMP3_TABLE: dict = {
    0:  ('filtered', 'net-unreachable'),
    1:  ('filtered', 'host-unreachable'),
    2:  ('filtered', 'proto-unreachable'),
    3:  ('closed',   'port-unreachable'),
    4:  ('filtered', 'fragmentation-needed'),
    5:  ('filtered', 'src-route-failed'),
    6:  ('filtered', 'dst-net-unknown'),
    7:  ('filtered', 'dst-host-unknown'),
    8:  ('filtered', 'src-host-isolated'),
    9:  ('firewall', 'net-admin-prohibited'),
    10: ('firewall', 'host-admin-prohibited'),
    11: ('filtered', 'net-tos-unreachable'),
    12: ('filtered', 'host-tos-unreachable'),
    13: ('firewall', 'comm-admin-prohibited'),
    14: ('firewall', 'host-precedence-violation'),
    15: ('firewall', 'precedence-cutoff'),
}

ICMP_TTL_EXCEEDED    = 11
ICMP_DEST_UNREACHABLE = 3

def classify_icmp3(code: int) -> Tuple[str, str]:
    return ICMP3_TABLE.get(code, ('filtered', f'icmp3-code{code}'))

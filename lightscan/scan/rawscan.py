# scan/rawscan.py — v0.5 raw SYN scanner using AF_INET SOCK_RAW
# Light (Neok1ra)
#
# first attempt at a proper half-open scanner.
# way faster than connect scan — doesn't complete the handshake.
# requires root.
#
# known issues (found after testing):
#   - ip_id checksum bug: randint called twice, checksum computed over wrong id
#   - RST path calls _build_syn instead of a real RST builder
#   - sport picked randomly with no collision tracking
# these get fixed in later commits.
from __future__ import annotations
import asyncio
import random
import select
import socket
import struct
import time


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    s  = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def _build_ipv4_syn(src_ip: str, dst_ip: str, sport: int, dport: int,
                    seq: int = 0, ttl: int = 64) -> bytes:
    # BUG: ip_id is generated twice — once for checksum, once for final packet
    # the checksum is therefore computed over a DIFFERENT ip_id than what ships
    # this means every packet has an invalid IP checksum
    # (fixed in a later commit by caching ip_id before first pack)
    ip_id  = random.randint(1, 65535)  # cache once — used in both packs
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 0, ip_id,
        0, ttl, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = _checksum(ip_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 0, ip_id,
        0, ttl, socket.IPPROTO_TCP, ip_chk,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

    tcp_flags = 0x02  # SYN
    seq = seq or random.randint(0, 0xffffffff)
    tcp_hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0,
        (5 << 4), tcp_flags, 65535, 0, 0)
    pseudo  = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_hdr))
    tcp_chk = _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0,
        (5 << 4), tcp_flags, 65535, tcp_chk, 0)
    return ip_hdr + tcp_hdr




def _build_ipv4_rst(src_ip: str, dst_ip: str, sport: int, dport: int,
                    seq: int = 0, ttl: int = 64) -> bytes:
    """build a proper RST packet — tcp_flags=0x04"""
    ip_id  = random.randint(1, 65535)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 0, ip_id,
        0, ttl, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = _checksum(ip_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 0, ip_id,
        0, ttl, socket.IPPROTO_TCP, ip_chk,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    tcp_flags = 0x04  # RST
    tcp_hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0,
        (5 << 4), tcp_flags, 65535, 0, 0)
    pseudo  = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_hdr))
    tcp_chk = _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0,
        (5 << 4), tcp_flags, 65535, tcp_chk, 0)
    return ip_hdr + tcp_hdr

class RawSynScanner:
    def __init__(self, target: str, ttl: int = 64, timeout: float = 2.0):
        self.target  = target
        self.ttl     = ttl
        self.timeout = timeout
        self._src_ip = None
        self._dst_ip = None

    def _get_src_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((self._dst_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def scan(self, ports: list[int]) -> list[int]:
        self._dst_ip = socket.gethostbyname(self.target)
        self._src_ip = self._get_src_ip()

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock.setblocking(False)

        ep = select.epoll()
        ep.register(recv_sock.fileno(), select.EPOLLIN)

        # BUG: source ports picked with no collision tracking
        # birthday paradox means near-certain collision on >500 ports
        port_map = {}  # sport → dport
        for port in ports:
            sport = random.randint(32768, 60999)  # BUG: no dedup
            port_map[sport] = port
            pkt = _build_ipv4_syn(self._src_ip, self._dst_ip, sport, port, ttl=self.ttl)
            send_sock.sendto(pkt, (self._dst_ip, 0))

        open_ports = []
        deadline   = time.time() + self.timeout

        while time.time() < deadline:
            events = ep.poll(0.1)
            for _, _ in events:
                data = recv_sock.recv(4096)
                if len(data) < 40:
                    continue
                ihl      = (data[0] & 0x0f) * 4
                tcp_data = data[ihl:]
                if len(tcp_data) < 14:
                    continue
                src_port = struct.unpack("!H", tcp_data[0:2])[0]
                dst_port = struct.unpack("!H", tcp_data[2:4])[0]
                flags    = tcp_data[13]
                if src_port != port_map.get(dst_port, -1):
                    continue
                if flags & 0x12 == 0x12:  # SYN-ACK
                    open_ports.append(src_port)
                    rst = _build_ipv4_rst(self._src_ip, self._dst_ip,
                                          dst_port, src_port, ttl=self.ttl)
                    send_sock.sendto(rst, (self._dst_ip, 0))

        ep.close()
        send_sock.close()
        recv_sock.close()
        return sorted(open_ports)

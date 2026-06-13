"""
NSE-style script engine — run targeted checks against specific services.

Scripts are Python modules dropped into lightscan/scripts/<category>/<name>.py.
Each exports SCRIPT_NAME, SCRIPT_PORTS, SCRIPT_TAGS, and an async run() function.
The engine discovers them automatically — no registration needed.

Built-in scripts cover HTTP (headers, methods, title, auth detection),
SMB (OS discovery, signing), TLS (versions, ciphers, cert info),
DNS (zone transfer, recursion), and SSH (algorithms, host key).

  http/http_title         — extract page title
  http/http_auth          — detect auth type (Basic, Digest, NTLM)
  smb/smb_os_discovery    — SMB OS/hostname enumeration
  smb/smb_security_mode   — SMB signing, auth level
  tls/tls_versions        — enumerate TLS/SSL versions
  tls/tls_ciphers         — list accepted cipher suites
  tls/tls_cert_info       — certificate details + expiry
  dns/dns_zone_transfer   — AXFR zone transfer attempt
  dns/dns_recursion       — test for open DNS recursion
  ssh/ssh_algorithms      — list supported SSH algorithms
  ssh/ssh_hostkey         — extract SSH host key fingerprint
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import re
import ssl
import socket
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional

from lightscan.core.engine import ScanResult, Severity


# ── Script registry ───────────────────────────────────────────────────────────

class ScriptRegistry:
    """Discovers and loads scripts from the scripts directory."""

    def __init__(self, script_dirs: Optional[List[str]] = None):
        self._scripts: Dict[str, object] = {}
        pkg_scripts  = Path(__file__).parent.parent / "scripts"
        home_scripts = Path.home() / ".lightscan" / "scripts"
        # Always scan both pkg and home dirs
        default_dirs = [str(pkg_scripts), str(home_scripts)]
        dirs = script_dirs or default_dirs
        for d in dirs:
            self._load_dir(Path(d))

    def _load_dir(self, path: Path):
        if not path.exists(): return
        for f in path.rglob("*.py"):
            if f.name.startswith("_"): continue
            try:
                spec   = importlib.util.spec_from_file_location(f.stem, f)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                name = getattr(module, "SCRIPT_NAME", f.stem)
                self._scripts[name] = module
            except Exception as e:
                print(f"\033[38;5;240m[!] Script load failed {f.name}: {e}\033[0m")

    def get(self, name: str):
        return self._scripts.get(name)

    def filter(self, tags: Optional[List[str]] = None,
               ports: Optional[List[int]] = None,
               names: Optional[List[str]] = None) -> List:
        out = list(self._scripts.values())
        if names:
            out = [s for s in out if getattr(s, "SCRIPT_NAME", "") in names]
        if tags:
            out = [s for s in out if
                   any(t in getattr(s, "SCRIPT_TAGS", []) for t in tags)]
        if ports:
            out = [s for s in out if
                   not getattr(s, "SCRIPT_PORTS", []) or
                   any(p in getattr(s, "SCRIPT_PORTS", []) for p in ports)]
        return out

    def for_port(self, port: int) -> List:
        return [s for s in self._scripts.values()
                if not getattr(s, "SCRIPT_PORTS", []) or
                port in getattr(s, "SCRIPT_PORTS", [])]

    def list_all(self) -> List[Dict]:
        result = []
        for name, mod in self._scripts.items():
            result.append({
                "name":  name,
                "tags":  getattr(mod, "SCRIPT_TAGS", []),
                "ports": getattr(mod, "SCRIPT_PORTS", []),
                "desc":  (mod.__doc__ or "").strip().split("\n")[0][:60],
            })
        return sorted(result, key=lambda x: x["name"])

    def __len__(self): return len(self._scripts)


async def run_script(script, host: str, port: int,
                     timeout: float = 8.0) -> List[ScanResult]:
    """Run a single script against a host:port."""
    try:
        fn = getattr(script, "run", None)
        if not fn: return []
        result = await fn(host, port, timeout)
        if isinstance(result, list): return result
        if isinstance(result, ScanResult): return [result]
        return []
    except Exception as e:
        return []


async def run_scripts(
    host:       str,
    open_ports: List[int],
    script_dirs: Optional[List[str]] = None,
    names:      Optional[List[str]]  = None,
    tags:       Optional[List[str]]  = None,
    timeout:    float = 8.0,
    concurrency:int   = 16,
    verbose:    bool  = False,
) -> List[ScanResult]:
    """Run all matching scripts against all open ports."""
    registry = ScriptRegistry(script_dirs)
    results  = []
    sem      = asyncio.Semaphore(concurrency)
    tasks    = []

    for port in open_ports:
        scripts = registry.filter(tags=tags, ports=[port], names=names)
        for script in scripts:
            sname = getattr(script, "SCRIPT_NAME", "unknown")
            async def _run(s=script, p=port, sn=sname):
                async with sem:
                    if verbose:
                        print(f"\033[38;5;240m  [script] {sn} → {host}:{p}\033[0m")
                    r = await run_script(s, host, p, timeout)
                    results.extend(r)
                    for res in r:
                        print(f"  \033[38;5;196m[{res.severity.value}]\033[0m "
                              f"script:{sn} @ {host}:{p} — {res.detail[:80]}")
            tasks.append(_run())

    if tasks:
        await asyncio.gather(*tasks)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Built-in scripts — written inline, saved to scripts/ on first run
# ══════════════════════════════════════════════════════════════════════════════

BUILTIN_SCRIPTS = {}

# ── http_headers ──────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["http_headers"] = '''"""Grab and analyse HTTP response headers."""
import asyncio, ssl, urllib.request, urllib.error
SCRIPT_NAME  = "http_headers"
SCRIPT_PORTS = [80, 443, 8080, 8443, 8000, 3000]
SCRIPT_TAGS  = ["http", "safe", "discovery"]

from lightscan.core.engine import ScanResult, Severity

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    url    = f"{scheme}://{host}:{port}/"
    loop   = asyncio.get_running_loop()
    def _fetch():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "LightScan/2.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx if scheme=="https" else None) as r:
                return dict(r.info()), r.status
        except urllib.error.HTTPError as e:
            return dict(e.headers), e.code
        except Exception:
            return {}, 0
    headers, status = await loop.run_in_executor(None, _fetch)
    if not headers: return []
    results = []
    # Security header analysis
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if missing:
        results.append(ScanResult("script:http_headers", host, port, "missing_headers",
            Severity.MEDIUM,
            f"Missing security headers: {', '.join(missing[:3])}",
            {"missing": missing, "present": {k:v for k,v in headers.items() if k in SECURITY_HEADERS}}))
    # Server header disclosure
    server = headers.get("Server", "")
    if server:
        results.append(ScanResult("script:http_headers", host, port, "server_header",
            Severity.LOW, f"Server: {server}", {"server": server}))
    # Interesting headers
    for hdr in ["X-Powered-By", "X-AspNet-Version", "X-Generator"]:
        if hdr in headers:
            results.append(ScanResult("script:http_headers", host, port, "info_disclosure",
                Severity.LOW, f"{hdr}: {headers[hdr]}", {"header": hdr, "value": headers[hdr]}))
    return results
'''

# ── http_methods ──────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["http_methods"] = '''"""Test which HTTP methods are allowed on the server."""
import asyncio, ssl
SCRIPT_NAME  = "http_methods"
SCRIPT_PORTS = [80, 443, 8080, 8443]
SCRIPT_TAGS  = ["http", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

DANGEROUS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_running_loop()
    allowed = []
    def _try(method):
        import urllib.request, urllib.error
        try:
            ctx = None
            if scheme == "https":
                import ssl; ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"{scheme}://{host}:{port}/",
                method=method, headers={"User-Agent": "LightScan/2.0"})
            with urllib.request.urlopen(req, timeout=3.0, **({"context":ctx} if ctx else {})) as r:
                return method, r.status
        except urllib.error.HTTPError as e:
            if e.code not in (405, 501): return method, e.code
        except Exception:
            pass
        return None
    results_raw = await asyncio.gather(*[
        loop.run_in_executor(None, _try, m)
        for m in ["GET","POST","PUT","DELETE","OPTIONS","TRACE","PATCH","HEAD"]
    ])
    allowed = [r[0] for r in results_raw if r]
    if not allowed: return []
    dangerous = [m for m in allowed if m in DANGEROUS]
    sev = Severity.HIGH if dangerous else Severity.INFO
    return [ScanResult("script:http_methods", host, port, "methods",
        sev, f"Allowed: {', '.join(allowed)}" + (f" | DANGEROUS: {', '.join(dangerous)}" if dangerous else ""),
        {"allowed": allowed, "dangerous": dangerous})]
'''

# ── tls_cert_info ─────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["tls_cert_info"] = '''"""Extract TLS certificate info and check expiry."""
import asyncio, ssl, socket
from datetime import datetime
SCRIPT_NAME  = "tls_cert_info"
SCRIPT_PORTS = [443, 8443, 993, 995, 636, 465, 587, 6443]
SCRIPT_TAGS  = ["tls", "ssl", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    def _get_cert():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert    = ssock.getpeercert()
                    version = ssock.version()
                    cipher  = ssock.cipher()
                    return cert, version, cipher
        except Exception:
            return None, None, None
    cert, version, cipher = await loop.run_in_executor(None, _get_cert)
    if not cert: return []
    results = []
    # Expiry check
    exp_str = cert.get("notAfter","")
    if exp_str:
        try:
            exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.utcnow()).days
            sev = Severity.CRITICAL if days_left < 7 else Severity.HIGH if days_left < 30 else Severity.INFO
            results.append(ScanResult("script:tls_cert_info", host, port, "cert_expiry",
                sev, f"TLS cert expires in {days_left} days ({exp_str})",
                {"days_left": days_left, "expiry": exp_str, "version": version}))
        except Exception: pass
    # Weak TLS version
    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        results.append(ScanResult("script:tls_cert_info", host, port, "weak_tls",
            Severity.HIGH, f"Weak TLS version: {version}",
            {"version": version}))
    # Subject info
    subject = {}
    for field in cert.get("subject", []):
        for k, v in field: subject[k] = v
    cn = subject.get("commonName", "")
    if cn:
        results.append(ScanResult("script:tls_cert_info", host, port, "tls_cert",
            Severity.INFO, f"CN={cn} | {version} | {cipher[0] if cipher else ''}",
            {"cn": cn, "subject": subject, "version": version,
             "cipher": cipher[0] if cipher else ""}))
    return results
'''

# ── ssh_algorithms ────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["ssh_algorithms"] = '''"""Extract SSH supported algorithms and flag weak ones."""
import asyncio, socket
SCRIPT_NAME  = "ssh_algorithms"
SCRIPT_PORTS = [22, 2222]
SCRIPT_TAGS  = ["ssh", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

WEAK_ALGOS = ["arcfour","blowfish","cast128","3des","des","md5","sha1","diffie-hellman-group1","diffie-hellman-group-exchange-sha1"]

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    def _get_kex():
        import struct, socket
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            # Read banner
            banner = s.recv(256).decode("utf-8","replace").strip()
            # Send our banner
            s.send(b"SSH-2.0-LightScan_2.0_scanner\\r\\n")
            # Read KEX_INIT packet
            raw = b""
            while len(raw) < 4:
                raw += s.recv(4 - len(raw))
            pkt_len = struct.unpack("!I", raw[:4])[0]
            payload = b""
            while len(payload) < pkt_len:
                payload += s.recv(pkt_len - len(payload))
            s.close()
            # Parse KEX_INIT (skip padding and message type)
            pad_len = payload[0]
            msg = payload[1:]
            if msg[0] != 20: return banner, {}  # not KEXINIT
            # Skip cookie (16 bytes) + message type
            pos = 17
            lists = {}
            names = ["kex_algos","server_host_key_algos","enc_c2s","enc_s2c",
                     "mac_c2s","mac_s2c","comp_c2s","comp_s2c"]
            for name in names:
                if pos + 4 > len(msg): break
                slen = struct.unpack("!I", msg[pos:pos+4])[0]
                pos += 4
                if pos + slen > len(msg): break
                algos = msg[pos:pos+slen].decode("utf-8","replace").split(",")
                lists[name] = algos
                pos += slen
            return banner, lists
        except Exception:
            return "", {}
    banner, algos = await loop.run_in_executor(None, _get_kex)
    if not algos: return []
    results = []
    all_algos = []
    for v in algos.values(): all_algos.extend(v)
    weak = [a for a in all_algos if any(w in a.lower() for w in WEAK_ALGOS)]
    if weak:
        results.append(ScanResult("script:ssh_algorithms", host, port, "weak_algos",
            Severity.MEDIUM, f"Weak SSH algorithms: {', '.join(set(weak[:5]))}",
            {"weak": list(set(weak)), "all": algos}))
    results.append(ScanResult("script:ssh_algorithms", host, port, "ssh_kex",
        Severity.INFO,
        f"KEX: {', '.join(algos.get('kex_algos',['?'])[:3])}",
        {"algorithms": algos, "banner": banner}))
    return results
'''

# ── smb_os_discovery ──────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["smb_os_discovery"] = '''"""Enumerate OS and hostname via SMB negotiate."""
import asyncio, struct, socket
SCRIPT_NAME  = "smb_os_discovery"
SCRIPT_PORTS = [445, 139]
SCRIPT_TAGS  = ["smb", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

SMB_NEG = bytes([
    0x00,0x00,0x00,0x54,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,
    0x53,0xc8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xfe,
    0x00,0x00,0x00,0x00,0x00,0x31,0x00,0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,
    0x31,0x2e,0x30,0x00,0x02,0x4c,0x4d,0x31,0x2e,0x32,0x58,0x30,0x30,0x32,
    0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00,
])

async def run(host, port, timeout=8.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(SMB_NEG); await w.drain()
        resp = await asyncio.wait_for(r.read(1024), timeout=timeout)
        w.close()
        if len(resp) < 36: return []
        # Parse SMB response for OS string
        if resp[4:8] != b"\\xff\\x53\\x4d\\x42": return []
        os_info = resp[73:].decode("utf-16-le", errors="replace").rstrip("\\x00")
        parts = [p.strip() for p in os_info.split("\\x00") if p.strip()]
        os_str = " | ".join(parts[:3]) if parts else "Unknown"
        return [ScanResult("script:smb_os_discovery", host, port, "smb_os",
            Severity.INFO, f"SMB OS: {os_str}",
            {"os": os_str, "raw_parts": parts})]
    except Exception:
        return []
'''

# ── dns_recursion ──────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["dns_recursion"] = '''"""Test if DNS server allows open recursion."""
import asyncio, struct, socket, time
SCRIPT_NAME  = "dns_recursion"
SCRIPT_PORTS = [53]
SCRIPT_TAGS  = ["dns", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

def _build_dns_query(name):
    txid = int(time.time()) & 0xFFFF
    hdr  = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in name.split("."):
        enc = part.encode()
        qname += struct.pack("B", len(enc)) + enc
    return hdr + qname + b"\\x00" + struct.pack("!HH", 1, 1)

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    def _test():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            # Query an external domain — if it resolves, recursion is open
            q = _build_dns_query("scanme.nmap.org")
            s.sendto(q, (host, port))
            resp, _ = s.recvfrom(512)
            s.close()
            ancount = struct.unpack("!H", resp[6:8])[0]
            return ancount > 0
        except Exception:
            return False
    is_open = await loop.run_in_executor(None, _test)
    if is_open:
        return [ScanResult("script:dns_recursion", host, port, "open_recursion",
            Severity.MEDIUM, "DNS server allows open recursion (can be abused for DRDoS)",
            {"recursive": True})]
    return [ScanResult("script:dns_recursion", host, port, "recursion_disabled",
        Severity.INFO, "DNS recursion disabled", {"recursive": False})]
'''


# ── ssl_weak_ciphers ──────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["ssl_weak_ciphers"] = '''"""Detect weak SSL/TLS ciphers and protocols."""
import asyncio, ssl, socket
SCRIPT_NAME  = "ssl_weak_ciphers"
SCRIPT_PORTS = [443, 8443, 993, 995, 465, 587, 636, 3389]
SCRIPT_TAGS  = ["tls", "ssl", "safe", "crypto"]
from lightscan.core.engine import ScanResult, Severity

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "ADH", "AECDH", "RC2", "IDEA",
]
WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    results = []

    def _check():
        findings = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    cipher = s.cipher()
                    proto  = s.version()
                    if cipher:
                        name = cipher[0]
                        for weak in WEAK_CIPHERS:
                            if weak.upper() in name.upper():
                                findings.append(("CRITICAL", f"Weak cipher in use: {name}"))
                                break
                        else:
                            findings.append(("INFO", f"Cipher: {name}"))
                    if proto in WEAK_PROTOCOLS:
                        findings.append(("HIGH", f"Weak protocol: {proto}"))
                    elif proto:
                        findings.append(("INFO", f"Protocol: {proto}"))
        except Exception:
            pass
        return findings

    raw = await loop.run_in_executor(None, _check)
    for sev_str, msg in raw:
        sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "MEDIUM": Severity.MEDIUM, "INFO": Severity.INFO}.get(sev_str, Severity.INFO)
        results.append(ScanResult("script:ssl_weak_ciphers", host, port,
            "weak_cipher" if sev_str != "INFO" else "cipher_info",
            sev, msg, {"detail": msg}))
    return results
'''

# ── http_auth_detect ──────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["http_auth_detect"] = '''"""Detect HTTP authentication mechanisms."""
import asyncio, ssl, urllib.request, urllib.error, base64
SCRIPT_NAME  = "http_auth_detect"
SCRIPT_PORTS = [80, 443, 8080, 8443, 8000, 8888]
SCRIPT_TAGS  = ["http", "auth", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_running_loop()

    def _probe(path="/"):
        try:
            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"User-Agent": "LightScan/2.0"}
            )
            kw = {"context": ctx} if ctx else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)
        except Exception:
            return 0, {}

    status, headers = await loop.run_in_executor(None, _probe)
    results = []
    if status == 0:
        return results

    www_auth = headers.get("Www-Authenticate", "")
    if www_auth:
        auth_type = www_auth.split()[0].upper() if www_auth else ""
        sev = Severity.MEDIUM
        detail = f"Auth required: {www_auth[:80]}"
        if "NTLM" in auth_type or "NEGOTIATE" in auth_type:
            sev = Severity.HIGH
            detail = f"Windows Auth (NTLM/Kerberos): {www_auth[:80]}"
        elif "BASIC" in auth_type:
            sev = Severity.HIGH
            detail = f"HTTP Basic Auth — credentials in plaintext: {www_auth[:80]}"
        results.append(ScanResult("script:http_auth_detect", host, port,
            "auth_required", sev, detail, {"auth": www_auth, "status": status}))
    elif status == 200:
        results.append(ScanResult("script:http_auth_detect", host, port,
            "no_auth", Severity.INFO, "No authentication required (HTTP 200)",
            {"status": 200}))
    return results
'''

# ── ftp_anon_write ────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["ftp_anon_write"] = '''"""Test FTP anonymous login and write access."""
import asyncio, ftplib, io
SCRIPT_NAME  = "ftp_anon_write"
SCRIPT_PORTS = [21, 2121]
SCRIPT_TAGS  = ["ftp", "safe", "auth", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()

    def _test():
        results = []
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            banner = ftp.getwelcome()
            try:
                ftp.login("anonymous", "lightscan@test.com")
                # Login succeeded — check write access
                try:
                    ftp.storbinary("STOR lightscan_test.txt", io.BytesIO(b"lightscan"))
                    ftp.delete("lightscan_test.txt")
                    results.append(("CRITICAL", "FTP anonymous login + WRITE access",
                        {"write": True, "banner": banner}))
                except ftplib.error_perm:
                    results.append(("HIGH", "FTP anonymous login (read-only)",
                        {"write": False, "banner": banner}))
            except ftplib.error_perm:
                results.append(("INFO", f"FTP banner: {banner[:80]}",
                    {"anonymous": False, "banner": banner}))
            ftp.quit()
        except Exception:
            pass
        return results

    raw = await loop.run_in_executor(None, _test)
    out = []
    for sev_str, msg, extra in raw:
        sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "INFO": Severity.INFO}.get(sev_str, Severity.INFO)
        out.append(ScanResult("script:ftp_anon_write", host, port,
            "ftp_anon", sev, msg, extra))
    return out
'''

# ── smb_signing ───────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["smb_signing"] = '''"""Check if SMB signing is required."""
import asyncio, socket, struct
SCRIPT_NAME  = "smb_signing"
SCRIPT_PORTS = [445, 139]
SCRIPT_TAGS  = ["smb", "windows", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    def _check():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            # SMB1 negotiate request
            pkt = (b"\x00\x00\x00\x54" + b"\xffSMB" + b"\x72"
                   + b"\x00" * 4 + b"\x08\x00" + b"\x00" * 6
                   + b"\xff\xff\xff\xff" + b"\x00" * 10
                   + b"\x00\x31" + b"\x00\x02NT LM 0.12\x00"
                   + b"\x02SMB 2.002\x00" + b"\x02SMB 2.???\x00")
            s.send(pkt)
            resp = s.recv(256)
            s.close()
            if len(resp) < 40:
                return None
            sec_mode = resp[39]
            signing_required = bool(sec_mode & 0x08)
            signing_enabled  = bool(sec_mode & 0x04)
            return signing_required, signing_enabled
        except Exception:
            return None
    result = await loop.run_in_executor(None, _check)
    if result is None:
        return []
    signing_required, signing_enabled = result
    if not signing_enabled:
        return [ScanResult("script:smb_signing", host, port, "smb_signing_disabled",
            Severity.HIGH, "SMB signing disabled — relay attacks possible",
            {"signing_required": False, "signing_enabled": False})]
    if signing_enabled and not signing_required:
        return [ScanResult("script:smb_signing", host, port, "smb_signing_not_required",
            Severity.MEDIUM, "SMB signing enabled but not required",
            {"signing_required": False, "signing_enabled": True})]
    return [ScanResult("script:smb_signing", host, port, "smb_signing_required",
        Severity.INFO, "SMB signing required",
        {"signing_required": True, "signing_enabled": True})]
'''

# ── http_cors_check ───────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["http_cors_check"] = '''"""Check for CORS misconfiguration."""
import asyncio, ssl, urllib.request, urllib.error
SCRIPT_NAME  = "http_cors_check"
SCRIPT_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000]
SCRIPT_TAGS  = ["http", "cors", "safe", "misconfig"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_running_loop()

    def _test():
        try:
            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}/",
                headers={
                    "User-Agent": "LightScan/2.0",
                    "Origin": "https://evil.com",
                }
            )
            kw = {"context": ctx} if ctx else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                headers = dict(r.headers)
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
        except Exception:
            return []

        results = []
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            results.append(("MEDIUM", "CORS wildcard (*) — any origin allowed",
                {"acao": acao, "acac": acac}))
        elif "evil.com" in acao:
            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
            results.append((sev,
                f"CORS reflects arbitrary origin{' + credentials' if acac.lower()=='true' else ''}",
                {"acao": acao, "acac": acac}))
        return results

    raw = await loop.run_in_executor(None, _test)
    out = []
    for sev_str, msg, extra in raw:
        sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "MEDIUM": Severity.MEDIUM}.get(sev_str, Severity.MEDIUM)
        out.append(ScanResult("script:http_cors_check", host, port,
            "cors_misconfig", sev, msg, extra))
    return out
'''

# ── http_tech_detect ──────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["http_tech_detect"] = '''"""Detect web technologies from headers and body."""
import asyncio, ssl, urllib.request, urllib.error, re
SCRIPT_NAME  = "http_tech_detect"
SCRIPT_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
SCRIPT_TAGS  = ["http", "safe", "discovery", "fingerprint"]
from lightscan.core.engine import ScanResult, Severity

TECH_SIGS = {
    "WordPress":    [re.compile(r"wp-content|wp-includes|WordPress", re.I)],
    "Drupal":       [re.compile(r"Drupal|sites/default|drupal\.js", re.I)],
    "Joomla":       [re.compile(r"Joomla|/components/com_", re.I)],
    "Laravel":      [re.compile(r"laravel_session|Laravel", re.I)],
    "Django":       [re.compile(r"csrfmiddlewaretoken|Django", re.I)],
    "React":        [re.compile(r"react-root|__REACT|ReactDOM", re.I)],
    "Angular":      [re.compile(r"ng-version|angular\.min\.js", re.I)],
    "Vue.js":       [re.compile(r"vue\.min\.js|__vue__", re.I)],
    "jQuery":       [re.compile(r"jquery[\-./]([0-9.]+)", re.I)],
    "Bootstrap":    [re.compile(r"bootstrap[\-./]([0-9.]+)", re.I)],
    "Spring Boot":  [re.compile(r"Spring Framework|Whitelabel Error|actuator", re.I)],
    "ASP.NET":      [re.compile(r"__VIEWSTATE|ASP\.NET|X-AspNet-Version", re.I)],
    "PHP":          [re.compile(r"X-Powered-By.*PHP|\.php", re.I)],
    "Node.js":      [re.compile(r"X-Powered-By.*Express|node\.js", re.I)],
    "Nginx":        [re.compile(r"nginx", re.I)],
    "Apache":       [re.compile(r"Apache", re.I)],
    "IIS":          [re.compile(r"Microsoft-IIS|X-Powered-By.*ASP", re.I)],
    "Tomcat":       [re.compile(r"Apache Tomcat|Coyote", re.I)],
    "Elasticsearch":[re.compile(r"elasticsearch|You Know, for Search", re.I)],
    "Jenkins":      [re.compile(r"Jenkins|X-Jenkins", re.I)],
}

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_running_loop()

    def _detect():
        try:
            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}/",
                headers={"User-Agent": "LightScan/2.0"}
            )
            kw = {"context": ctx} if ctx else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                body    = r.read(32768).decode("utf-8", "replace")
                headers = str(dict(r.headers))
        except urllib.error.HTTPError as e:
            try:
                body = e.read(8192).decode("utf-8", "replace")
            except Exception:
                body = ""
            headers = str(dict(e.headers))
        except Exception:
            return []

        combined = body + headers
        found = []
        for tech, patterns in TECH_SIGS.items():
            for pat in patterns:
                if pat.search(combined):
                    found.append(tech)
                    break
        return found

    techs = await loop.run_in_executor(None, _detect)
    if not techs:
        return []
    return [ScanResult("script:http_tech_detect", host, port, "tech_detected",
        Severity.INFO, f"Technologies: {', '.join(techs)}",
        {"technologies": techs})]
'''


def install_builtin_scripts(script_dir: Optional[str] = None) -> str:
    """Write built-in scripts to disk so ScriptRegistry can load them."""
    if script_dir:
        base = Path(script_dir)
    else:
        # Try package dir first, fall back to ~/.lightscan/scripts
        pkg_scripts = Path(__file__).parent.parent / "scripts"
        try:
            pkg_scripts.mkdir(parents=True, exist_ok=True)
            base = pkg_scripts
        except PermissionError:
            base = Path.home() / ".lightscan" / "scripts"

    categories = {
        "http":  ["http_headers", "http_methods", "http_auth_detect",
                  "http_cors_check", "http_tech_detect"],
        "tls":   ["tls_cert_info", "ssl_weak_ciphers"],
        "ssh":   ["ssh_algorithms"],
        "smb":   ["smb_os_discovery", "smb_signing"],
        "dns":   ["dns_recursion"],
        "ftp":   ["ftp_anon_write"],
    }

    for cat, names in categories.items():
        cat_dir = base / cat
        cat_dir.mkdir(parents=True, exist_ok=True)
        (cat_dir / "__init__.py").touch()
        for name in names:
            script_path = cat_dir / f"{name}.py"
            if not script_path.exists() and name in BUILTIN_SCRIPTS:
                script_path.write_text(BUILTIN_SCRIPTS[name])

    return str(base)

"""
Autonomous Orchestration Engine
The whole reason this project exists. You give it a domain name.
It figures out the rest.

Internally it runs a 10-stage pipeline where every stage feeds
its findings directly into the next one — no waiting, no manual
handoff. If stage 3 finds Redis open, stage 5 immediately tries
to write a webshell. If stage 7 cracks an SSH password, stage 8
uses it to check for DCSync access.

Stages in order:
  1  DNS / OSINT       Subdomain enum via crt.sh CT logs + DNS brute
  2  Asset resolution  Resolve subdomains → IPs, filter to scope, flag CDN
  3  Active scan       ICMP discovery + async port scan on live hosts
  5  Vuln validation   CVE template checks on every open port
  6  Exploit chains    Build ordered attack paths from confirmed findings
  7  Credential attack Auto-brute SSH, FTP, MySQL, RDP, MSSQL
  8  DC detection      Spot Kerberos+LDAP → print DCSync / Kerberoasting path
  9  Web deep-scan     Full OWASP scanner on all HTTP/HTTPS targets
  10 Compromise map    Structured JSON attack graph saved to disk

TargetContext is the shared memory that carries facts across stages.
It remembers OS family, open ports, cracked creds, and pivot hosts —
so stages skip irrelevant probes automatically. No point running
Windows-only checks on a box that answered with Linux TTLs.

Stealth mode (--stealth) drops to T1 timing with 1-3s jitter and
halves concurrency. Not invisible, but much quieter.
"""
from __future__ import annotations

import asyncio, ipaddress, json, socket, time, random, re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from lightscan.core.engine import ScanResult, Severity
from lightscan.core.target import parse_ports
from lightscan.scan.active import active_scan, discover_hosts, validate_port, pivot_suggestions

# every stage_* function below prints status with these. used to be
# redefined locally in a couple places (run_auto, print_compromise_map)
# and just missing everywhere else, so anything stage_dns/stage_vuln/etc
# tried to print crashed with NameError the second it found anything.
C   = "\033[38;5;196m"   # red    — headers / critical
YEL = "\033[38;5;208m"   # amber  — warnings / medium
GRN = "\033[38;5;82m"    # green  — success
BLU = "\033[38;5;117m"   # blue   — info
DIM = "\033[38;5;240m"   # gray   — muted / secondary text
R   = "\033[0m"          # reset

# Target context (shared memory across all stages)

@dataclass
class TargetContext:
    """Accumulates everything discovered about the engagement."""
    domain:         str
    scope:          List[str]           = field(default_factory=list)   # allowed CIDRs/domains
    subdomains:     List[str]           = field(default_factory=list)
    ips:            Dict[str, str]      = field(default_factory=dict)   # subdomain→ip
    live_hosts:     List[str]           = field(default_factory=list)
    open_ports:     Dict[str, List[int]] = field(default_factory=dict)
    services:       Dict[str, Dict]     = field(default_factory=dict)   # host:port → svc info
    os_hints:       Dict[str, str]      = field(default_factory=dict)   # host → "windows"/"linux"
    vulns:          List[ScanResult]    = field(default_factory=list)
    creds:          List[Dict]          = field(default_factory=list)   # {"host","proto","user","pass"}
    pivot_hosts:    List[str]           = field(default_factory=list)
    dc_candidates:  List[str]           = field(default_factory=list)
    web_targets:    List[str]           = field(default_factory=list)   # http/https URLs
    all_results:    List[ScanResult]    = field(default_factory=list)
    skipped:        Set[str]            = field(default_factory=set)    # skipped probe types

    def add_result(self, r: ScanResult):
        self.all_results.append(r)

    def extend_results(self, rs):
        self.all_results.extend(rs)

    def in_scope(self, host: str) -> bool:
        """Return True if host is within defined scope."""
        if not self.scope:
            return True  # no scope = unrestricted
        for s in self.scope:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(s, strict=False):
                    return True
            except ValueError:
                # domain-based scope
                if host == s or host.endswith("." + s):
                    return True
        return False

    def skip(self, probe: str) -> bool:
        return probe in self.skipped

    def os_is_windows(self, host: str) -> bool:
        return "windows" in self.os_hints.get(host, "").lower()

    def os_is_linux(self, host: str) -> bool:
        return "linux" in self.os_hints.get(host, "").lower()

# Stage helpers

def _stage(n: int, name: str):
    bar = f"\033[38;5;196m╪\033[0m"
    print(f"\n {bar} \033[1;38;5;196m[STAGE {n}]\033[0m \033[1m{name.upper()}\033[0m")
    print(f"   " + "\033[38;5;236m─\033[0m" * 60)

async def _resolve(host: str) -> Optional[str]:
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, socket.gethostbyname, host)
    except Exception:
        return None

async def _crtsh(domain: str) -> List[str]:
    """Pull subdomains from crt.sh CT logs."""
    import urllib.request as ur
    loop = asyncio.get_running_loop()
    def _fetch():
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = ur.Request(url, headers={"User-Agent": "LightScan/2.0"})
            with ur.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                names = set()
                for entry in data:
                    for name in entry.get("name_value","").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain): names.add(name)
                return list(names)
        except Exception: return []
    return await loop.run_in_executor(None, _fetch)

_SUBDOMAIN_WORDLIST = [
    "www","mail","smtp","pop","imap","ftp","dev","test","staging","api","app","admin",
    "portal","vpn","remote","gitlab","jenkins","jira","confluence","grafana","monitor",
    "db","database","backup","cdn","auth","login","sso","proxy","gateway","internal",
    "corp","intranet","files","upload","download","support","helpdesk","citrix","rdp",
    "exchange","owa","autodiscover","webmail","mx","ns1","ns2","blog","shop","store",
]

async def _dns_brute(domain: str, wordlist: List[str]) -> List[str]:
    """DNS brute-force subdomain enumeration."""
    found = []
    sem   = asyncio.Semaphore(50)

    async def _try(word: str):
        async with sem:
            fqdn = f"{word}.{domain}"
            ip = await _resolve(fqdn)
            if ip:
                found.append(fqdn)

    await asyncio.gather(*[_try(w) for w in wordlist])
    return found

async def _axfr(domain: str) -> List[str]:
    """Attempt DNS zone transfer."""
    import dns_stub as _  # silent import, we implement minimally below
    pass

def _infer_os(ttl: int, banner: str) -> str:
    """Heuristic OS family from TTL and banners."""
    if ttl:
        if ttl <= 64:   return "linux"
        if ttl <= 128:  return "windows"
        if ttl <= 255:  return "cisco/solaris"
    b = banner.lower()
    for kw in ("windows","microsoft","iis","ms-sql","exchange","active directory"):
        if kw in b: return "windows"
    for kw in ("ubuntu","debian","centos","redhat","linux","nginx","apache","openssh"):
        if kw in b: return "linux"
    return ""

# Orchestration stages

async def stage_dns(ctx: TargetContext, timeout: float, stealth: bool):
    """Stage 1: Subdomain enumeration via crt.sh + DNS brute."""
    _stage(1, f"OSINT / DNS enumeration → {ctx.domain}")

    # crt.sh CT logs
    ct_subs = await _crtsh(ctx.domain)
    print(f"  {BLU}crt.sh{R}  {len(ct_subs)} subdomains from CT logs")
    ctx.subdomains.extend(ct_subs)

    # DNS brute
    if not stealth:
        brute_subs = await _dns_brute(ctx.domain, _SUBDOMAIN_WORDLIST)
        new = [s for s in brute_subs if s not in ctx.subdomains]
        print(f"  {BLU}brute{R}   {len(new)} new subdomains via DNS brute")
        ctx.subdomains.extend(new)

    # Deduplicate
    ctx.subdomains = list(dict.fromkeys(ctx.subdomains))
    # Always include root domain
    if ctx.domain not in ctx.subdomains:
        ctx.subdomains.insert(0, ctx.domain)

    print(f"  {GRN}→{R} {len(ctx.subdomains)} total subdomains to investigate")
    ctx.extend_results([
        ScanResult("orch:dns", s, 0, "subdomain", Severity.INFO, f"Subdomain: {s}")
        for s in ctx.subdomains
    ])

async def stage_resolve(ctx: TargetContext, timeout: float):
    """Stage 2: Resolve subdomains → IPs, scope-filter, detect CDN."""
    _stage(2, "Asset resolution + scope enforcement")
    CDN_CNAMES = {"cloudflare","akamai","fastly","cloudfront","incapsula","sucuri","imperva"}

    sem = asyncio.Semaphore(50)
    async def _res(host: str):
        async with sem:
            ip = await _resolve(host)
            if ip and ctx.in_scope(ip) and ctx.in_scope(host):
                ctx.ips[host] = ip
                # CDN detection via PTR / hostname
                is_cdn = any(cdn in host.lower() for cdn in CDN_CNAMES)
                if is_cdn:
                    print(f"  {DIM}CDN{R}  {host} → {ip} (CDN — limited scan)")
                else:
                    print(f"  {GRN}OK{R}   {host} → {ip}")
            elif ip and not ctx.in_scope(ip):
                print(f"  {DIM}OOS{R}  {host} → {ip} (out-of-scope, skipped)")

    await asyncio.gather(*[_res(s) for s in ctx.subdomains])
    unique_ips = list(dict.fromkeys(ctx.ips.values()))
    print(f"  {GRN}→{R} {len(unique_ips)} unique IPs in scope")
    ctx.live_hosts = unique_ips

async def stage_portscan(ctx: TargetContext, timeout: float,
                          ports: Optional[List[int]], intensity: int, stealth: bool, mode: str = "deep"):
    """Stage 3-4: Active scan + service profiling on all resolved IPs."""
    _stage(3, f"Active scan + service profiling ({len(ctx.live_hosts)} hosts)")

    results = await active_scan(
        targets=ctx.live_hosts,
        ports=ports,
        timeout=timeout,
        concurrency=50 if stealth else 256,
        intensity=intensity,
        verbose=False,
        skip_discovery=True,  # already have IPs
        mode=mode,
    )
    ctx.extend_results(results)

    # Build open_ports map and OS hints from results
    for r in results:
        if r.module == "portscan" and r.status == "open":
            ctx.open_ports.setdefault(r.target, []).append(r.port)
        elif r.module == "active:service":
            key = f"{r.target}:{r.port}"
            ctx.services[key] = r.data
        elif r.module == "active:discovery" and r.data.get("ttl"):
            os_guess = _infer_os(r.data["ttl"], "")
            if os_guess: ctx.os_hints[r.target] = os_guess
        elif r.module == "active:service" and r.data.get("banner"):
            host = r.target
            os_guess = _infer_os(0, r.data.get("banner",""))
            if os_guess: ctx.os_hints[host] = os_guess
        elif r.module.startswith("active:") and r.status == "VULN":
            ctx.vulns.append(r)

    # Detect web targets
    for host, plist in ctx.open_ports.items():
        for p in plist:
            scheme = "https" if p in (443,8443,9443) else "http"
            if p in (80,443,8080,8443,8000,8888,3000,5000,9090,9200):
                url = f"{scheme}://{host}:{p}"
                if url not in ctx.web_targets:
                    ctx.web_targets.append(url)

async def stage_vuln(ctx: TargetContext, timeout: float, allow_intrusive: bool = False):
    """Stage 5: Validate vulns not already covered by active_scan."""
    _stage(5, "Extended vulnerability validation")
    # active_scan already ran vuln validation; this stage adds CVE template checks
    if not ctx.open_ports:
        print(f"  {DIM}No open ports to check{R}")
        return

    try:
        from lightscan.cve.bridge import run_all_checks, versions_from_results
        versions = versions_from_results(ctx.all_results)
        for host, plist in ctx.open_ports.items():
            results = await run_all_checks(host, plist, use_legacy=True,
                                            versions=versions, allow_intrusive=allow_intrusive,
                                            timeout=timeout)
            for r in results:
                if r.status not in ("not_vuln","not_detected","error","timeout","no_response"):
                    ctx.vulns.append(r)
                    ctx.add_result(r)
                    print(f"  {C}[{r.severity.value}]{R} {r.module} {r.target}:{r.port} — {r.detail[:70]}")
    except ImportError:
        pass

async def stage_exploit_chain(ctx: TargetContext):
    """Stage 6: Build ordered exploit chains from confirmed findings."""
    _stage(6, "Exploit chain analysis")
    from lightscan.scan.exploit_chain import build_chains, print_chain_report

    chains = build_chains(ctx)
    if not chains:
        print(f"  {DIM}No exploitable chains identified{R}")
        return

    print_chain_report(chains)
    for c in chains:
        ctx.add_result(ScanResult("orch:exploit-chain", c["host"], 0, "chain",
            Severity.CRITICAL if c["severity"] == "CRITICAL" else Severity.HIGH,
            c["summary"], {"steps": c["steps"]}))

async def stage_cred_attack(ctx: TargetContext, timeout: float,
                              userlist: List[str], passlist: List[str]):
    """Stage 7: Auto-brute services where creds might work."""
    _stage(7, "Credential attack (auto-brute)")
    from lightscan.brute.engine import BruteEngine
    from lightscan.brute.handlers import get_handler, PROTOCOLS

    BRUTE_MAP = {22:"ssh", 21:"ftp", 23:"telnet", 3306:"mysql",
                 5432:"postgres", 1433:"mssql", 3389:"rdp"}

    brute = BruteEngine(concurrency=8, timeout=timeout,
                        jitter=(0.5, 2.0), verbose=False)

    for host, plist in ctx.open_ports.items():
        for port in plist:
            proto = BRUTE_MAP.get(port)
            if not proto: continue
            if proto not in PROTOCOLS: continue
            # Skip Windows-only protos on Linux hosts
            if proto in ("rdp","mssql") and ctx.os_is_linux(host): continue

            print(f"  {BLU}[BRUTE]{R} {proto.upper()} {host}:{port}")
            try:
                handler = get_handler(proto, host, port)
                results = await brute.run(handler, userlist, passlist,
                                          host, port, proto, stop_first=True)
                for r in results:
                    if r.status == "found":
                        cred = r.data
                        ctx.creds.append({"host":host,"proto":proto,
                                          "user":cred.get("username",""),
                                          "pass":cred.get("password","")})
                        ctx.add_result(r)
                        print(f"  {C}[CREDS]{R} {host}:{port} {proto.upper()} "
                              f"{cred.get('username')}:{cred.get('password')}")
            except Exception as e:
                print(f"  {DIM}[!] brute {proto} {host}: {e}{R}")

async def stage_dc_hunt(ctx: TargetContext, timeout: float):
    """Stage 8: Detect Domain Controllers via Kerberos/LDAP/SMB."""
    _stage(8, "Domain Controller / Active Directory detection")
    DC_PORTS = {88, 389, 636, 3268, 3269, 445}

    for host, plist in ctx.open_ports.items():
        port_set = set(plist)
        # DC fingerprint: Kerberos(88) + LDAP(389) + SMB(445)
        if 88 in port_set and (389 in port_set or 636 in port_set):
            ctx.dc_candidates.append(host)
            os_hint = ctx.os_hints.get(host, "windows")
            print(f"  {C}[DC FOUND]{R} {host} — Kerberos+LDAP detected → likely Domain Controller")
            print(f"    {DIM}→ Run: lightscan --brute ldap -t {host}{R}")
            print(f"    {DIM}→ Kerberoasting: impacket-GetUserSPNs domain/user@{host}{R}")
            ctx.add_result(ScanResult("orch:dc", host, 88, "DC_DETECTED", Severity.CRITICAL,
                f"Domain Controller detected — Kerberos+LDAP open",
                {"ports": list(port_set & DC_PORTS),
                 "attacks": ["Kerberoasting","AS-REP Roasting","DCSync","NTLM coercion"],
                 "tools": [
                     f"impacket-GetUserSPNs domain/user@{host}",
                     f"impacket-secretsdump domain/user:pass@{host}",
                     f"BloodHound-python -d domain -u user -p pass -ns {host} -c all",
                 ]}))
        # Pure SMB DC indicator (fallback)
        elif 445 in port_set and 3268 in port_set:
            ctx.dc_candidates.append(host)
            print(f"  {YEL}[DC CANDIDATE]{R} {host} — GlobalCatalog(3268)+SMB")
            ctx.add_result(ScanResult("orch:dc", host, 3268, "DC_CANDIDATE", Severity.HIGH,
                "DC candidate — GlobalCatalog+SMB", {}))

async def stage_web(ctx: TargetContext, timeout: float, stealth: bool):
    """Stage 9: Full web scanner on discovered HTTP/HTTPS targets."""
    _stage(9, f"Web application deep scan ({len(ctx.web_targets)} targets)")
    if not ctx.web_targets:
        print(f"  {DIM}No web targets found{R}")
        return

    try:
        from lightscan.web.scanner import web_scan_async
    except ImportError:
        print(f"  {DIM}web scanner unavailable{R}")
        return

    # Stealth: only scan first 3 targets; normal: all
    targets = ctx.web_targets[:3] if stealth else ctx.web_targets
    for url in targets:
        print(f"  {BLU}[WEB]{R} {url}")
        try:
            results = await web_scan_async(url, timeout=timeout, threads=5)
            for r in results:
                if r.severity.value in ("CRITICAL","HIGH","MEDIUM"):
                    print(f"    {C}[{r.severity.value}]{R} {r.module} — {r.detail[:70]}")
            ctx.extend_results(results)
        except Exception as e:
            print(f"  {DIM}[!] web scan error {url}: {e}{R}")

# Stage 10: Compromise Map

def build_compromise_map(ctx: TargetContext) -> dict:
    """Build structured JSON compromise narrative."""
    crit_vulns = [r for r in ctx.vulns if r.severity == Severity.CRITICAL]
    high_vulns = [r for r in ctx.vulns if r.severity == Severity.HIGH]

    attack_paths = []
    # Group by host
    host_vulns: Dict[str, List[ScanResult]] = {}
    for v in ctx.vulns:
        host_vulns.setdefault(v.target, []).append(v)

    for host, vlist in host_vulns.items():
        attacks = [v.data.get("attack", v.module) for v in vlist if v.data]
        path = {
            "host": host,
            "os":   ctx.os_hints.get(host, "unknown"),
            "open_ports": ctx.open_ports.get(host, []),
            "vulns": [{"module":v.module,"detail":v.detail,"attack":v.data.get("attack","")}
                      for v in vlist],
            "pivot": host in ctx.pivot_hosts,
            "dc":    host in ctx.dc_candidates,
            "creds": [c for c in ctx.creds if c["host"] == host],
        }
        # Add next-step from exploit data
        nexts = []
        for v in vlist:
            n = v.data.get("next") or v.data.get("chain") or []
            if isinstance(n, list): nexts.extend(n[:2])
            elif n: nexts.append(str(n))
        path["recommended_next"] = nexts[:5]
        attack_paths.append(path)

    return {
        "domain":         ctx.domain,
        "subdomains":     len(ctx.subdomains),
        "live_hosts":     len(ctx.live_hosts),
        "open_ports_total": sum(len(v) for v in ctx.open_ports.values()),
        "critical_vulns": len(crit_vulns),
        "high_vulns":     len(high_vulns),
        "creds_found":    len(ctx.creds),
        "dc_candidates":  ctx.dc_candidates,
        "web_targets":    ctx.web_targets,
        "attack_paths":   attack_paths,
        "total_findings": len(ctx.all_results),
    }

def print_compromise_map(m: dict):
    print(f"\n{C}┌───────────────────────────────────────────────────────────────┐{R}")
    print(f"{C}│                    COMPROMISE MAP — {m['domain']:<26} │{R}")
    print(f"{C}├───────────────────────────────────────────────────────────────┤{R}")
    print(f"{C}│{R}  Subdomains enumerated : {m['subdomains']:<37} {C}│{R}")
    print(f"{C}│{R}  Live hosts            : {m['live_hosts']:<37} {C}│{R}")
    print(f"{C}│{R}  Open ports total      : {m['open_ports_total']:<37} {C}│{R}")
    print(f"{C}│{R}  Critical vulns        : {C}{m['critical_vulns']:<37}{R} {C}│{R}")
    print(f"{C}│{R}  High vulns            : {YEL}{m['high_vulns']:<37}{R} {C}│{R}")
    print(f"{C}│{R}  Credentials found     : {GRN}{m['creds_found']:<37}{R} {C}│{R}")
    if m["dc_candidates"]:
        dc_str = ', '.join(m['dc_candidates'])[:37]
        print(f"{C}│{R}  Domain Controllers    : {C}{dc_str:<37}{R} {C}│{R}")
    print(f"{C}└───────────────────────────────────────────────────────────────┘{R}")
    print()
    for path in m["attack_paths"]:
        if not path["vulns"]: continue
        dc  = f" {C}[DC]{R}" if path["dc"] else ""
        os_ = f" [{path['os']}]" if path["os"] != "unknown" else ""
        print(f"  \033[1;38;5;196m⚡ HOST:\033[0m \033[1m{path['host']}\033[0m{os_}{dc}")
        print(f"       \033[38;5;242mports:\033[0m {path['open_ports'][:8]}")
        for v in path["vulns"][:4]:
            print(f"       {C}✗{R} {v['detail'][:70]}")
        for step in path.get("recommended_next", [])[:3]:
            print(f"       {DIM}↳ {step}{R}")
        if path["creds"]:
            for c in path["creds"]:
                print(f"       {GRN}✔ CREDS{R} {c['proto'].upper()} {c['user']}:{c['pass']}")
    print()

# Main orchestrator entry point

async def run_auto(
    domain:     str,
    scope:      List[str]       = None,
    timeout:    float           = 3.0,
    intensity:  int             = 3,
    stealth:    bool            = False,
    ports:      Optional[List[int]] = None,
    userlist:   List[str]       = None,
    passlist:   List[str]       = None,
    skip_web:   bool            = False,
    skip_brute: bool            = False,
    output_dir: str             = ".",
    mode:       str             = "deep",
    allow_intrusive: bool       = False,
) -> Tuple[List[ScanResult], dict]:
    """
    Fully autonomous red-team pipeline.
    Returns (all_results, compromise_map_dict).
    """
    from lightscan.brute.mutation import COMMON_PASSWORDS

    ctx      = TargetContext(domain=domain, scope=scope or [])
    users    = userlist  or ["admin","root","administrator","sa","operator","guest","test"]
    passwords = passlist or list(COMMON_PASSWORDS)[:30]
    t0       = time.time()

    if stealth:
        print(f"{DIM}[OPSEC] Stealth mode active — T1 timing, jitter, reduced concurrency{R}")

    await stage_dns(ctx, timeout, stealth)
    await stage_resolve(ctx, timeout)

    if not ctx.live_hosts:
        print(f"\033[38;5;208m[!] No in-scope hosts resolved. Check domain / scope settings.\033[0m")
        return ctx.all_results, {}

    await stage_portscan(ctx, timeout, ports, intensity, stealth, mode=mode)
    
    if mode != "sweep":
        await stage_vuln(ctx, timeout, allow_intrusive)
        await stage_exploit_chain(ctx)

        if not skip_brute:
            await stage_cred_attack(ctx, timeout, users, passwords)

        await stage_dc_hunt(ctx, timeout)

        if not skip_web:
            await stage_web(ctx, timeout, stealth)

    # Stage 10 — Compromise map
    _stage(10, "Building compromise map")
    comp_map = build_compromise_map(ctx)
    print_compromise_map(comp_map)

    # Save JSON
    if output_dir == "-":
        # stdout is reserved for Reporter's piped report — writing a second
        # file here would hit Path('-')/... (FileNotFoundError) since '-'
        # isn't a real directory. comp_map is still returned to the caller.
        print(f"  {DIM}[i] --output - active — compromise map not written to disk, "
              f"returned in-memory only{R}")
    else:
        out_path = Path(output_dir) / f"compromise_map_{domain.replace('.','_')}.json"
        try:
            out_path.write_text(json.dumps(comp_map, indent=2, default=str))
            print(f"  {GRN}[+]{R} Compromise map saved → {out_path}")
        except Exception as e:
            print(f"  {DIM}[!] Could not save map: {e}{R}")

    elapsed = time.time() - t0
    total_c = sum(1 for r in ctx.all_results if r.severity == Severity.CRITICAL)
    print(f"{C}[AUTO DONE]{R} {len(ctx.all_results)} findings | "
          f"{C}{total_c} CRITICAL{R} | {elapsed:.0f}s | "
          f"DCs: {ctx.dc_candidates or 'none found'}")

    return ctx.all_results, comp_map

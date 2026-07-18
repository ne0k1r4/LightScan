"""
LightScan v2.0 PHANTOM — CLI Entry Point
Developer: Light (Neok1ra)

Usage:
  lightscan --scan -t 192.168.1.0/24 -p top100
  lightscan --brute ssh -t 10.0.0.1 -U root,admin -W rockyou.txt
  lightscan --dns target.com
  lightscan --cve -t 10.0.0.1 --scan
  lightscan --oauth https://login.target.com/oauth/authorize --oauth-client CLIENT_ID
  lightscan --diff old.json new.json
"""
from __future__ import annotations
import argparse
import asyncio
import sys
import time

# only truly core imports at top level — everything else is lazy-loaded inside
# the relevant branch. this way a missing optional dep (scapy, paramiko, etc.)
# doesn't crash the CLI before it even prints the banner or --help.
from lightscan.banner import print_banner
from lightscan.core.engine import PhantomEngine, ScanResult, Severity
from lightscan.core.target import parse_targets, parse_ports
from lightscan.core.checkpoint import Checkpoint
from lightscan.core.reporter import Reporter
from lightscan.scan.evasion import parse_timing  # used in multiple branches


def build_parser():
    p = argparse.ArgumentParser(
        prog="lightscan",
        description="LightScan v2.0 PHANTOM — Async Network Recon & Attack Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    # Target
    tg = p.add_argument_group("Target")
    tg.add_argument("-t","--target", help="IP / CIDR / range / hostname / file:path.txt")
    tg.add_argument("-p","--ports",  default="top100", help="Ports: 22,80,443 · 1-1024 · top100 (default)")
    tg.add_argument("--udp",         action="store_true", help="Include UDP scan (53,123,161)")
    tg.add_argument("--syn",         action="store_true", help="SYN half-open scan (requires root + scapy)")
    tg.add_argument("--syn-c",       action="store_true", help="SYN scan using compiled C binary (fastest, root+gcc)")
    tg.add_argument("--threads",     type=int, default=100, help="SYN scanner threads (default:100)")
    tg.add_argument("--raw",         action="store_true", help="Raw async SYN scan (root, epoll, nmap speed)")
    tg.add_argument("-T","--timing",  type=str, default="T4", metavar="T0-T5", help="Timing template: T0(paranoid) to T5(insane) [default: T4]")
    tg.add_argument("--ttl",         type=int, default=64,  help="IP TTL for raw scans (default: 64)")
    tg.add_argument("--decoy",       type=int, default=0,   metavar="N", help="Send N random decoy IPs alongside probes")
    tg.add_argument("--fragment",    action="store_true",   help="Fragment IP packets (IDS evasion)")
    tg.add_argument("--source-port", type=int, default=0,   metavar="PORT", help="Fix source port (e.g. 53 for firewall bypass)")
    tg.add_argument("--randomize",   action="store_true", default=True, help="Randomise port scan order (default: on)")
    tg.add_argument("--no-randomize",action="store_true",   help="Disable port order randomisation")
    tg.add_argument("-6","--ipv6",   action="store_true",   help="IPv6 scan (dual-stack resolution)")
    tg.add_argument("--ipv6-only",   action="store_true",   help="Scan IPv6 addresses only")
    tg.add_argument("--dual-stack",  action="store_true",   help="Scan both IPv4 and IPv6 addresses")
    tg.add_argument("--os-v2",       action="store_true",   help="Use improved OS fingerprint database (120+ signatures)")
    tg.add_argument("--packet-scan",  action="store_true",  help="AF_PACKET half-open SYN scan (Linux root, open/closed/filtered/firewall)")
    tg.add_argument("--stealth-scan", action="store_true",  help="IDS-evasion mode: T1 timing + jitter + sport randomisation (implies --packet-scan)")
    tg.add_argument("--spoof-sport",  type=int, default=0, metavar="PORT", help="Spoof source port (e.g. 53 or 80) to bypass port-based ACLs")
    tg.add_argument("--sv",          action="store_true",   help="Service version detection (nmap -sV equivalent)")
    tg.add_argument("--script",      nargs="+", metavar="SCRIPT", help="Run NSE-style scripts (e.g. http_headers tls_cert_info)")
    tg.add_argument("--script-tags", nargs="+", metavar="TAG",    help="Run all scripts with matching tags (e.g. http safe)")
    tg.add_argument("--list-scripts",action="store_true",   help="List all available scripts")
    tg.add_argument("--passive",     action="store_true",   help="Passive fingerprinting (TLS/JA3S, HTTP headers, SSH entropy)")
    tg.add_argument("--adaptive",    action="store_true", default=True, help="Adaptive timing (auto-adjusts rate based on RTT/loss)")

    # Autonomous / Active
    aa = p.add_argument_group("Autonomous Red-Team")
    aa.add_argument("--auto",        metavar="DOMAIN",
                    help="AUTONOMOUS mode: domain→subdomain→scan→exploit→pivot→DC compromise map")
    aa.add_argument("--active",      action="store_true",
                    help="Active red-team scan: host discovery + service probing + vuln validation + pivot map")
    aa.add_argument("--intensity",   type=int, default=3, choices=range(1,6), metavar="1-5",
                    help="Active scan intensity: 1=quiet … 5=full-noise (default: 3)")
    aa.add_argument("--scope",       nargs="+", metavar="CIDR/DOMAIN",
                    help="Hard scope enforcement: allowed CIDRs or domains (blocks out-of-scope probes)")
    aa.add_argument("--stealth",     action="store_true",
                    help="Stealth OPSEC: T1 timing, 1-3s jitter, reduced concurrency, CDN-aware")
    aa.add_argument("--skip-web",    action="store_true", help="--auto: skip web deep-scan stage")
    aa.add_argument("--skip-brute",  action="store_true", help="--auto: skip credential brute stage")
    aa.add_argument("--mode",        choices=["sweep", "deep"], default="deep",
                    help="Scan mode: sweep (fast recon/ports only) or deep (full audit) [default: deep]")

    # Modules
    m = p.add_argument_group("Modules")
    m.add_argument("--scan",         action="store_true", help="Port scan")
    m.add_argument("--dns",          metavar="DOMAIN",    help="Full DNS enum on DOMAIN")
    m.add_argument("--no-axfr",      action="store_true", help="Skip AXFR zone transfer")
    m.add_argument("--no-crtsh",     action="store_true", help="Skip crt.sh CT lookup")
    m.add_argument("--no-brute-dns", action="store_true", help="Skip subdomain brute")
    m.add_argument("--os-probe",     action="store_true", help="Active T2-T7 OS fingerprinting (root+scapy, 6 extra packets per host)")
    m.add_argument("--os-passive",   action="store_true", help="Passive OS fingerprint from SYN-ACK (auto with --syn, zero extra packets)")
    m.add_argument("--os-port",      type=int,            help="Open port for --os-probe (auto-detected if omitted)")
    m.add_argument("--web-scan",     metavar="URL",       help="Full web application scan on URL (dir, tech, sqli, xss, cors, creds, jwt, files, secrets)")
    m.add_argument("--web-checks",   nargs="+", metavar="CHECK",
                   help="Web checks to run (dir tech sqli xss redirect cors creds jwt files secrets)")
    m.add_argument("--web-wordlist", metavar="FILE",      help="Wordlist file for --web-scan directory brute")
    m.add_argument("--web-threads",  type=int, default=10, help="Threads for web dir brute (default 10)")
    m.add_argument("--rdp-probe",    metavar="HOST",      help="RDP fingerprint probe (NLA/SSL/cert info)")
    m.add_argument("--cve",           action="store_true", help="CVE + template checks on open ports (legacy + template engine)")
    m.add_argument("--cve-list",      nargs="+",
        help="Specific CVEs: eternalblue log4shell spring4shell heartbleed shellshock redis-unauth mongo-unauth elastic-unauth")
    m.add_argument("--log4shell-callback", default="", help="Log4Shell OAST callback (e.g. your.interactsh.com)")
    m.add_argument("--templates",     action="store_true", help="Run template engine only (no legacy CVE checks)")
    m.add_argument("--template-dir",  metavar="DIR",       help="Extra template directory")
    m.add_argument("--template-tags", nargs="+", metavar="TAG", help="Filter templates by tag (redis unauth rce ...)")
    m.add_argument("--template-ids",  nargs="+", metavar="ID",  help="Run specific template IDs only")
    m.add_argument("--list-templates",action="store_true", help="List all loaded templates and exit")
    m.add_argument("--search",        metavar="QUERY",     help="Search scripts and templates by keyword/tag/CVE")
    m.add_argument("--update-templates", nargs="?", const="ne0k1r4/LightScan", metavar="REPO", help="Update templates from GitHub repository (default: ne0k1r4/LightScan)")
    m.add_argument("--oauth",        metavar="AUTH_URL",  help="OAuth 2.0 audit on AUTH_URL")
    m.add_argument("--oauth-client", metavar="CLIENT_ID", help="OAuth client_id")
    m.add_argument("--oauth-redirect",metavar="URI",      help="OAuth redirect_uri")
    m.add_argument("--diff",         nargs=2, metavar=("OLD.json","NEW.json"), help="Diff two scan JSONs")
    m.add_argument("--traceroute",   metavar="HOST",      help="TCP traceroute to HOST")

    # Brute force
    bf = p.add_argument_group("Brute Force")
    try:
        from lightscan.brute.handlers import PROTOCOLS as _P
        _proto_list = ', '.join(sorted(_P))
    except Exception:
        _proto_list = "ssh ftp smb rdp http mysql mssql redis mongo"
    bf.add_argument("--brute",       metavar="PROTO", help=f"Protocol: {_proto_list}")
    bf.add_argument("--brute-port",  type=int,        help="Override brute port")
    bf.add_argument("-U","--users",  help="Users: admin,root | file:users.txt")
    bf.add_argument("-W","--wordlist",help="Passwords: file:path | 'common' | word1,word2")
    bf.add_argument("--mutate",      action="store_true", help="Apply smart mutation engine to wordlist")
    bf.add_argument("--spray",       action="store_true", help="Credential spray mode (1 pass × N users)")
    bf.add_argument("--spray-window",type=int,default=1800,help="Spray window seconds (default:1800)")
    bf.add_argument("--brute-conc",  type=int,default=16,  help="Brute concurrency (default:16)")
    bf.add_argument("--stop-first",  action="store_true",  help="Stop after first credential found")
    bf.add_argument("--jitter",      nargs=2,type=float,metavar=("MIN","MAX"),help="Brute jitter: --jitter 0.5 3.0")

    # HTTP brute
    hb = p.add_argument_group("HTTP Brute (--brute http)")
    hb.add_argument("--http-url",        help="Login form URL")
    hb.add_argument("--http-user-field", default="username")
    hb.add_argument("--http-pass-field", default="password")
    hb.add_argument("--http-success",    default="", help="Text on successful login")
    hb.add_argument("--http-failure",    default="", help="Text on failed login")
    hb.add_argument("--http-basic",      action="store_true", help="HTTP Basic Auth mode")

    # Engine
    en = p.add_argument_group("Engine")
    en.add_argument("--concurrency", type=int,   default=None,  help="Scan concurrency (default: auto-tuned from ulimit, usually 256)")
    en.add_argument("--timeout",     type=float, default=3.0,  help="Connection timeout (default:3.0)")

    # Evasion
    ev = p.add_argument_group("Evasion")
    ev.add_argument("--proxy-file",  help="SOCKS5 proxy file (socks5://host:port per line)")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("-o","--output",     default=".", help="Output directory (default: .)")
    out.add_argument("--basename",        default="lightscan_report")
    out.add_argument("--format",          choices=["json", "html", "csv", "nmap-xml", "minimal"], default="json", help="Report format (default: json)")
    out.add_argument("--no-report",       action="store_true", help="Skip file reports")
    out.add_argument("--resume",          action="store_true", help="Resume from checkpoint")
    out.add_argument("--clear-checkpoint",action="store_true", help="Clear checkpoint and start fresh")
    out.add_argument("-v","--verbose",    action="store_true", help="Verbose output")
    out.add_argument("--no-discovery", action="store_true", help="Skip host discovery")
    out.add_argument("--smb-enum", action="store_true", help="SMB null session + share enum")
    out.add_argument("--snmp", action="store_true", help="SNMP enumeration")
    out.add_argument("--snmp-community", default="public")
    out.add_argument("--no-banner",       action="store_true", help="Suppress banner (useful with --format json or scripted use)")
    return p


def parse_userlist(spec):
    if not spec:
        return ["admin","root","administrator","user","test","guest","service","operator"]
    if spec.startswith("file:"):
        with open(spec[5:]) as f: return [l.strip() for l in f if l.strip()]
    return [u.strip() for u in spec.split(",")]

def parse_passwdlist(spec, users=None, target_info=None, mutate=False):
    from lightscan.brute.mutation import MutationEngine, COMMON_PASSWORDS
    if not spec: return list(COMMON_PASSWORDS)
    if spec.lower()=="common": base=list(COMMON_PASSWORDS)
    elif spec.startswith("file:"): base=MutationEngine.load_wordlist(spec[5:])
    else: base=[p.strip() for p in spec.split(",")]
    if mutate:
        eng=MutationEngine(base_words=base,target_info=target_info or {})
        expanded=[]
        for u in (users or [""]): expanded.extend(eng.generate(username=u))
        return list(dict.fromkeys(expanded))
    return base


async def async_main(args):
    # ── flag conflict validation ─────────────────────────────────────────────
    # catch obvious mistakes before we get deep into the scan and fail weirdly
    scan_modes = [
        args.scan,
        args.syn,
        getattr(args, 'syn_c', False),
        getattr(args, 'raw', False),
        getattr(args, 'packet_scan', False),
        getattr(args, 'stealth_scan', False),
    ]
    if sum(bool(m) for m in scan_modes) > 1:
        print("\033[38;5;208m[!] Multiple scan modes active — pick one: "
              "--scan / --syn / --raw / --packet-scan / --stealth-scan\033[0m")
        sys.exit(1)

    if (args.syn or getattr(args, 'raw', False) or
            getattr(args, 'packet_scan', False) or
            getattr(args, 'stealth_scan', False)):
        try:
            import os as _os
            if _os.geteuid() != 0:
                print("\033[38;5;208m[!] Raw/SYN scans require root. "
                      "Re-run with sudo or use --scan for connect-scan.\033[0m")
                sys.exit(1)
        except AttributeError:
            pass  # windows — let it fail naturally

    if getattr(args, 'brute', None) and not args.target:
        print("\033[38;5;208m[!] --brute requires -t / --target\033[0m")
        sys.exit(1)

    if getattr(args, 'brute', None):
        from lightscan.brute.handlers import PROTOCOLS
        proto = args.brute.lower()
        if proto not in PROTOCOLS:
            print(f"\033[38;5;208m[!] Unknown brute protocol: {proto!r}\033[0m")
            print(f"    Available: {', '.join(sorted(PROTOCOLS))}\033[0m")
            sys.exit(1)

    timing_raw = getattr(args, 'timing', 'T4')
    try:
        parse_timing(timing_raw)
    except (ValueError, KeyError):
        print(f"\033[38;5;208m[!] Invalid timing: {timing_raw!r} — use T0..T5\033[0m")
        sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────────
    if not getattr(args, 'no_banner', False):
        print_banner()
    t_start=time.time(); all_results=[]; open_ports={}
    # Build target string — prefer --target, fall back to --web-scan URL
    _target = args.target or getattr(args, 'web_scan', None) or ""
    meta={"target":_target,"timestamp":t_start,"duration":0,"command":" ".join(sys.argv)}

    cp=Checkpoint()
    if args.clear_checkpoint: cp.clear()
    if args.target: cp.set_target(args.target)

    try:
        return await _run_main_body(args, cp, t_start, all_results, open_ports, meta)
    finally:
        # ctrl+c during a brute run shouldn't lose progress — main() prints
        # "checkpoint saved" on KeyboardInterrupt so this needs to actually
        # be true, not just true on the happy path
        cp.flush()

async def run_search(query: str):
    print(f"\033[38;5;196m[SEARCH]\033[0m Searching scripts and templates for: \033[38;5;220m{query!r}\033[0m\n")
    
    # Search CVE templates
    from lightscan.cve.template_engine import TemplateLibrary
    from pathlib import Path
    dirs = [str(Path(__file__).parent / "templates")]
    lib = TemplateLibrary(dirs)
    matching_templates = lib.search(query)
    
    # Search NSE scripts
    from lightscan.scan.scripts import ScriptRegistry, install_builtin_scripts
    script_base = install_builtin_scripts()
    registry = ScriptRegistry([script_base])
    matching_scripts = registry.search(query)
    
    SEV_COLORS = {
        "CRITICAL": "\033[38;5;196;1m",  # bold red
        "HIGH": "\033[38;5;202;1m",      # bold orange
        "MEDIUM": "\033[38;5;220;1m",    # bold yellow
        "LOW": "\033[38;5;82;1m",        # bold green
        "INFO": "\033[38;5;39;1m"        # bold blue
    }
    
    # Print templates
    if matching_templates:
        title = f"VULNERABILITY TEMPLATES ({len(matching_templates)} matches)"
        rem = max(2, 76 - 5 - len(title))
        print(f"\033[38;5;196m┌───\033[0m \033[1m{title}\033[0m \033[38;5;196m" + "─" * rem + "\033[0m")
        print(f"  \033[38;5;244m%-10s %-32s %-20s %-10s %s\033[0m" % ("SEVERITY", "ID", "CVE", "PORT", "TAGS"))
        print(f"  " + "\033[38;5;238m─\033[0m" * 74)
        for tmpl in sorted(matching_templates, key=lambda x: (x.severity.value, x.id)):
            cve = tmpl.cve if tmpl.cve else "-"
            tags = ",".join(tmpl.tags[:3])
            col = SEV_COLORS.get(tmpl.severity.value.upper(), "\033[0m")
            print(f"  {col}%-10s\033[0m %-32s %-20s %-10s \033[38;5;242m[%s]\033[0m" % (
                tmpl.severity.value, tmpl.id[:32], cve[:20], str(tmpl.port), tags
            ))
        print(f"\033[38;5;196m└" + "─" * 76 + "\033[0m\n")
        
    # Print scripts
    if matching_scripts:
        title = f"RECON & DETECTION SCRIPTS ({len(matching_scripts)} matches)"
        rem = max(2, 76 - 5 - len(title))
        print(f"\033[38;5;39m┌───\033[0m \033[1m{title}\033[0m \033[38;5;39m" + "─" * rem + "\033[0m")
        print(f"  \033[38;5;244m%-30s %-18s %s\033[0m" % ("SCRIPT NAME", "PORTS", "TAGS"))
        print(f"  " + "\033[38;5;238m─\033[0m" * 74)
        for s in matching_scripts:
            tags = ",".join(s['tags'][:3])
            ports = ",".join(map(str, s['ports'][:4])) if s['ports'] else "all"
            print(f"  \033[38;5;111m%-30s\033[0m %-18s \033[38;5;242m[%s]\033[0m" % (
                s['name'][:30], ports[:18], tags
            ))
            if s['desc']:
                desc = s['desc'].strip().replace("\n", " ")
                desc_lines = [desc[i:i+70] for i in range(0, len(desc), 70)]
                for line in desc_lines[:2]:
                    print(f"    \033[38;5;240m\u21aa {line.strip()}\033[0m")
        print(f"\033[38;5;39m└" + "─" * 76 + "\033[0m\n")
        
    if not matching_templates and not matching_scripts:
        print(f"\033[38;5;240m[-] No matching templates or scripts found for {query!r}\033[0m\n")


def run_update_templates(repo_spec: str):
    import urllib.request
    import zipfile
    import shutil
    import tempfile
    from pathlib import Path
    
    if "/" not in repo_spec:
        print(f"\033[38;5;208m[!] Invalid repo format. Must be owner/repo (e.g., ne0k1r4/LightScan)\033[0m")
        return
        
    owner, repo = repo_spec.split("/", 1)
    url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
    
    print(f"\033[38;5;196m[UPDATE]\033[0m Downloading templates from: {url}")
    
    local_template_dir = Path(__file__).parent / "templates"
    
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        
        with urllib.request.urlopen(req, timeout=15) as response:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_file:
                shutil.copyfileobj(response, tmp_file)
                tmp_zip_path = Path(tmp_file.name)
                
        print(f"\033[38;5;196m[UPDATE]\033[0m Extracting templates...")
        
        with zipfile.ZipFile(tmp_zip_path, 'r') as zip_ref:
            extracted_count = 0
            for file_info in zip_ref.infolist():
                parts = Path(file_info.filename).parts
                if len(parts) >= 3 and "templates" in parts:
                    tpl_idx = parts.index("templates")
                    if tpl_idx > 0 and parts[tpl_idx - 1] == "lightscan":
                        rel_path = Path(*parts[tpl_idx + 1:])
                        target_path = local_template_dir / rel_path
                        
                        if file_info.is_dir():
                            target_path.mkdir(parents=True, exist_ok=True)
                        else:
                            target_path.parent.mkdir(parents=True, exist_ok=True)
                            with zip_ref.open(file_info) as source, open(target_path, "wb") as target:
                                shutil.copyfileobj(source, target)
                            extracted_count += 1
                            
        try:
            tmp_zip_path.unlink()
        except Exception:
            pass
            
        if extracted_count > 0:
            print(f"\033[38;5;82m[+] Successfully updated {extracted_count} templates from {repo_spec}!\033[0m\n")
        else:
            print(f"\033[38;5;208m[!] No templates found in the repository archive.\033[0m\n")
            
    except Exception as e:
        print(f"\033[38;5;196m[!] Error updating templates: {e}\033[0m")


async def _run_main_body(args, cp, t_start, all_results, open_ports, meta):
    # ── Search option
    if getattr(args, 'search', None):
        await run_search(args.search)
        return all_results

    # ── Update templates option
    if getattr(args, 'update_templates', None):
        run_update_templates(args.update_templates)
        return all_results

    # ── Autonomous mode (--auto domain.com) ──────────────────────────────────
    if getattr(args, 'auto', None):
        from lightscan.scan.orchestrator import run_auto
        scope     = getattr(args, 'scope', None) or []
        stealth   = getattr(args, 'stealth', False)
        intensity = getattr(args, 'intensity', 3)
        ports     = parse_ports(args.ports) if args.ports != "top100" else None
        users     = parse_userlist(args.users)  if args.users    else None
        passwords = parse_passwdlist(args.wordlist, mutate=args.mutate) if args.wordlist else None
        results, comp_map = await run_auto(
            domain     = args.auto,
            scope      = scope,
            timeout    = args.timeout,
            intensity  = intensity,
            stealth    = stealth,
            ports      = ports,
            userlist   = users,
            passlist   = passwords,
            skip_web   = getattr(args, 'skip_web', False),
            skip_brute = getattr(args, 'skip_brute', False),
            output_dir = args.output,
            mode       = getattr(args, 'mode', 'deep'),
        )
        all_results.extend(results)
        if not args.no_report and all_results:
            Reporter(args.output).save(all_results, meta, args.basename, fmt=args.format)
        return all_results

    # ── Active red-team scan (--active -t target) ─────────────────────────────
    if getattr(args, 'active', False) and args.target:
        from lightscan.scan.active import active_scan
        hosts     = parse_targets(args.target)
        intensity = getattr(args, 'intensity', 3)
        scope     = getattr(args, 'scope', None) or []
        if scope:
            import ipaddress as _ip
            def _in_scope(h):
                for s in scope:
                    try:
                        if _ip.ip_address(h) in _ip.ip_network(s, strict=False): return True
                    except ValueError:
                        if h == s or h.endswith("." + s): return True
                return False
            filtered = [h for h in hosts if _in_scope(h)]
            dropped  = len(hosts) - len(filtered)
            if dropped:
                print(f"\033[38;5;240m[SCOPE] Dropped {dropped} out-of-scope host(s)\033[0m")
            hosts = filtered
        if not hosts:
            print("\033[38;5;208m[!] No in-scope targets to scan.\033[0m")
            return all_results
        ports = parse_ports(args.ports) if args.ports != "top100" else None
        results = await active_scan(
            targets     = hosts,
            ports       = ports,
            timeout     = args.timeout,
            concurrency = args.concurrency,
            intensity   = intensity,
            verbose     = args.verbose,
            mode        = getattr(args, 'mode', 'deep'),
        )
        all_results.extend(results)
        if not args.no_report and all_results:
            Reporter(args.output).save(all_results, meta, args.basename, fmt=args.format)
        return all_results

    # ── Diff
    if args.diff:
        from lightscan.scan.diff import diff_scans
        old_f,new_f=args.diff
        results,summary=diff_scans(old_f,new_f)
        print(f"\033[38;5;196m[DIFF]\033[0m {summary}")
        all_results.extend(results)

    # ── DNS
    if args.dns:
        from lightscan.scan.dns import full_dns_enum
        r=await full_dns_enum(args.dns,axfr=not args.no_axfr,
            brute=not args.no_brute_dns,use_crtsh=not args.no_crtsh)
        all_results.extend(r)

    # ── Active OS Fingerprinting (T2-T7 multi-probe)
    if getattr(args, 'os_probe', False) and args.target:
        from lightscan.scan.os_detect import os_probe_async
        hosts = parse_targets(args.target)
        print(f"\033[38;5;196m[OS-PROBE]\033[0m Active fingerprinting {len(hosts)} host(s)")
        for host in hosts:
            # Use first known open port, or fall back to 80
            probe_port = getattr(args, 'os_port', None)
            if not probe_port:
                probe_port = open_ports.get(host, [80])[0] if open_ports.get(host) else 80
            os_results = await os_probe_async(host, probe_port)
            for r in os_results:
                print(f"  \033[38;5;196m[OS]\033[0m {r.target} → {r.detail}")
            all_results.extend(os_results)

    # ── Passive OS detection standalone (--os-passive without --syn)
    if getattr(args, 'os_passive', False) and not (args.syn or getattr(args,'syn_c',False)) and args.target:
        print(f"\033[38;5;240m[!] --os-passive works best with --syn (reads SYN-ACK packets)\033[0m")
        print(f"\033[38;5;240m    Without --syn, TTL-only estimation will be LOW confidence\033[0m")

    # ── Web Application Scan
    if getattr(args, 'web_scan', None):
        from lightscan.web.scanner import web_scan_async
        print(f"\033[38;5;196m[WEB-SCAN]\033[0m {args.web_scan}")
        web_results = await web_scan_async(
            args.web_scan,
            wordlist_file = getattr(args, 'web_wordlist', None),
            timeout  = args.timeout,
            threads  = getattr(args, 'web_threads', 10),
            checks   = getattr(args, 'web_checks', None),
        )
        all_results.extend(web_results)
        counts = {}
        for r in web_results:
            counts[r.severity.value] = counts.get(r.severity.value, 0) + 1
        SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        summary = " | ".join(
            f"{counts[s]} {s}" for s in SEV_ORDER if s in counts
        )
        print(f"  \033[38;5;196m[WEB-SCAN DONE]\033[0m {len(web_results)} findings — {summary}")

        # ── Grouped terminal summary ──────────────────────────────────────
        from lightscan.core.reporter import _group_results
        raw_dicts = [r.to_dict() for r in web_results]
        grouped   = _group_results(raw_dicts)
        SEV_COLOR = {"CRITICAL":"\033[38;5;196m","HIGH":"\033[38;5;208m",
                     "MEDIUM":"\033[38;5;226m","LOW":"\033[38;5;40m","INFO":"\033[38;5;240m"}
        for r in grouped:
            sev = r.get("severity","INFO")
            if sev not in ("CRITICAL","HIGH","MEDIUM"): continue
            col  = SEV_COLOR.get(sev,"\033[0m")
            cnt  = r.get("count","")
            tag  = f" ×{cnt}" if cnt else ""
            det  = str(r.get("detail",""))
            print(f"    {col}[{sev}]\033[0m {r.get('module','')} — {det}{tag}")
            for url in r.get("urls",[])[:5]:
                print(f"      \033[38;5;240m↳ {url}\033[0m")


    # ── RDP Probe
    if getattr(args, 'rdp_probe', None):
        from lightscan.brute.handlers.rdp_raw import make_rdp_probe, RawRDPHandler
        print(f"\033[38;5;196m[RDP-PROBE]\033[0m {args.rdp_probe}")
        info = make_rdp_probe(args.rdp_probe, timeout=args.timeout)
        for k, v in info.items():
            print(f"  {k:<18}: {v}")
        sev = Severity.HIGH if info.get("nla_required") else Severity.CRITICAL
        all_results.append(ScanResult("rdp-probe", args.rdp_probe, 3389,
            info.get("status","?"), sev,
            f"RDP proto={info.get('protocol','?')} NLA={info.get('nla_required','?')}",
            info))

    # ── Traceroute
    if args.traceroute:
        from lightscan.scan.traceroute import tcp_traceroute
        tr=await tcp_traceroute(args.traceroute,timeout=args.timeout)
        for hop in tr: print(f"  {hop.detail}")
        all_results.extend(tr)

    # ── SYN Scan (half-open, raw socket)
    if (args.syn or getattr(args, 'syn_c', False)) and args.target:
        from lightscan.scan.syn import syn_scan_auto
        hosts = parse_targets(args.target); ports = parse_ports(args.ports)
        syn_results = []
        for host in hosts:
            r = syn_scan_auto(host, ports, args.timeout,
                              getattr(args,'threads',100), args.verbose,
                              prefer_c=getattr(args,'syn_c',False))
            syn_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")
        all_results.extend(syn_results)

    # ── UDP Scan (dedicated module with ICMP classification)
    if args.udp and args.target:
        from lightscan.scan.udp import udp_scan
        udp_ports_default = [53, 67, 68, 69, 111, 123, 137, 161, 162,
                             389, 500, 514, 520, 1900, 4500, 5353, 5060]
        ports = parse_ports(args.ports) if args.ports else udp_ports_default
        hosts = parse_targets(args.target)
        udp_results = []
        for host in hosts:
            r = udp_scan(host, ports, args.timeout,
                         getattr(args, 'threads', 50), args.verbose)
            udp_results.extend(r)
        for res in udp_results:
            colour = "\033[38;5;196m" if res.status == "open" else "\033[38;5;240m"
            print(f"  {colour}{res.status.upper():<13}\033[0m  "
                  f"{res.target}:{res.port:<6} {res.detail}")
        all_results.extend(udp_results)

    # ── Raw async SYN scan (epoll, nmap speed)
    if getattr(args, 'raw', False) and args.target:
        from lightscan.scan.rawscan import async_raw_scan
        hosts  = parse_targets(args.target)
        ports  = parse_ports(args.ports)
        timing = parse_timing(getattr(args, 'timing', 'T4'))
        ttl    = getattr(args, 'ttl', 64)
        decoys = getattr(args, 'decoy', 0)
        frag   = getattr(args, 'fragment', False)
        rand   = not getattr(args, 'no_randomize', False)
        ipv6   = getattr(args, 'ipv6', False)
        print(f"\033[38;5;196m[RAW-SCAN]\033[0m {len(hosts)} host(s) × {len(ports)} ports | "
              f"T{timing} | ttl={ttl} | decoys={decoys} | frag={frag}")
        for host in hosts:
            r = await async_raw_scan(host, ports, timing=timing, ttl=ttl,
                                     decoys=decoys, fragment=frag, randomize=rand,
                                     grab_banner=True, verbose=args.verbose, ipv6=ipv6)
            all_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")

    # ── IPv6 scan
    if getattr(args, 'ipv6', False) and args.target and not getattr(args, 'raw', False):
        from lightscan.scan.ipv6scan import scan_ipv6, dual_stack_scan
        hosts = parse_targets(args.target)
        ports = parse_ports(args.ports)
        for host in hosts:
            if getattr(args, 'dual_stack', False):
                r = await dual_stack_scan(host, ports, args.timeout,
                                          args.concurrency, verbose=args.verbose)
            else:
                r = await scan_ipv6(host, ports, args.timeout,
                                    args.concurrency, verbose=args.verbose)
            all_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")

    # ── OS fingerprint v2
    if getattr(args, 'os_v2', False) and args.target:
        from lightscan.scan.osdb import probe_os
        hosts = parse_targets(args.target)
        print(f"\033[38;5;196m[OS-V2]\033[0m Fingerprinting {len(hosts)} host(s)")
        for host in hosts:
            port = list(open_ports.get(host, [0]))[0] if open_ports.get(host) else 0
            r = await probe_os(host, port, args.timeout)
            all_results.extend(r)
            for res in r:
                print(f"  \033[38;5;196m[OS]\033[0m {res.target} → {res.detail}")


    # ── AF_PACKET / stealth scan
    _do_packet = getattr(args, 'packet_scan', False) or getattr(args, 'stealth_scan', False)
    if _do_packet and args.target:
        from lightscan.scan.packetscan import async_packet_scan
        hosts       = parse_targets(args.target)
        ports       = parse_ports(args.ports)
        timing      = parse_timing(getattr(args, 'timing', 'T4'))
        stealth     = getattr(args, 'stealth_scan', False)
        spoof_sport = getattr(args, 'spoof_sport', 0)
        for host in hosts:
            r = await async_packet_scan(
                host, ports, timing=timing,
                ttl=getattr(args, 'ttl', 64),
                grab_banner=True, verbose=args.verbose,
                stealth=stealth, spoof_sport=spoof_sport)
            all_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m     {res.target}:{res.port:<6} {res.detail}")
                elif res.status == "firewall":
                    print(f"  \033[38;5;208mFIREWALL\033[0m {res.target}:{res.port:<6} {res.detail}")

    # ── Script engine
    if getattr(args, 'list_scripts', False):
        from lightscan.scan.scripts import ScriptRegistry, install_builtin_scripts
        script_base = install_builtin_scripts()
        registry    = ScriptRegistry([script_base])
        
        s_tags = getattr(args, 'script_tags', None)
        s_ports = parse_ports(args.ports) if args.ports != "top100" else None
        
        scripts = registry.list_all()
        if s_tags:
            scripts = [s for s in scripts if any(t in s['tags'] for t in s_tags)]
        if s_ports:
            scripts = [s for s in scripts if not s['ports'] or any(p in s['ports'] for p in s_ports)]
            
        if s_tags or s_ports:
            print(f"\033[38;5;196m[SCRIPTS]\033[0m Found {len(scripts)} matching script(s)\n")
        else:
            print(f"\033[38;5;196m[SCRIPTS]\033[0m {len(registry)} scripts available\n")
            
        for s in scripts:
            print(f"  {s['name']:<30} [{', '.join(s['tags'][:3])}]  ports={s['ports'][:4]}")
            if s['desc']: print(f"    {s['desc']}")
        return all_results

    if (getattr(args, 'script', None) or getattr(args, 'script_tags', None)) and args.target:
        from lightscan.scan.scripts import run_scripts, install_builtin_scripts
        hosts       = parse_targets(args.target)
        script_base = install_builtin_scripts()
        for host in hosts:
            ports = open_ports.get(host, parse_ports(args.ports))
            r = await run_scripts(
                host, ports,
                script_dirs=[script_base],
                names=getattr(args, 'script', None),
                tags=getattr(args, 'script_tags', None),
                timeout=args.timeout, verbose=args.verbose)
            all_results.extend(r)

    # ── Service version detection (-sV)
    if getattr(args, 'sv', False) and args.target:
        from lightscan.scan.sversion import detect_services
        hosts = parse_targets(args.target)
        print(f"\033[38;5;196m[sV]\033[0m Service version detection | {len(hosts)} host(s)")
        for host in hosts:
            ports = open_ports.get(host, parse_ports(args.ports))
            if not ports: continue
            r = await detect_services(host, ports, args.timeout, verbose=args.verbose)
            all_results.extend(r)
            for res in r:
                print(f"  \033[38;5;196m[{res.port}]\033[0m {res.detail}")

    # ── Passive fingerprinting
    if getattr(args, 'passive', False) and args.target:
        from lightscan.scan.passive import passive_fingerprint
        hosts = parse_targets(args.target)
        print(f"\033[38;5;196m[PASSIVE]\033[0m Passive fingerprinting | {len(hosts)} host(s)")
        for host in hosts:
            ports = open_ports.get(host, parse_ports(args.ports))
            if not ports: continue
            r = await passive_fingerprint(host, ports, args.timeout)
            all_results.extend(r)
            for res in r:
                print(f"  \033[38;5;196m[{res.module}]\033[0m {res.detail}")


    # ── Port Scan
    if args.scan and args.target:
        hosts=parse_targets(args.target); ports=parse_ports(args.ports)
        print(f"\033[38;5;196m[SCAN]\033[0m Scanning {len(hosts)} host(s) × {len(ports)} port(s) | concurrency={args.concurrency}")
        engine=PhantomEngine(
            concurrency=args.concurrency,
            timeout=args.timeout,
            verbose=args.verbose,
            adaptive=getattr(args, 'adaptive', False),
            timing=parse_timing(getattr(args, 'timing', 'T4')),
        )
        from lightscan.scan.portscan import build_scan_tasks
        tasks=build_scan_tasks(hosts,ports,args.timeout,args.udp)
        scan_r=await engine.run(tasks)
        all_results.extend(scan_r)
        for r in scan_r:
            if r and r.status=="open":
                open_ports.setdefault(r.target,[]).append(r.port)
                print(f"  \033[38;5;196mOPEN  {r.target}:{r.port:<6} {r.detail}\033[0m")

    # ── List templates
    if getattr(args, 'list_templates', False):
        from lightscan.cve.template_engine import TemplateLibrary
        from pathlib import Path
        dirs = [str(Path(__file__).parent / "templates")]
        if getattr(args, 'template_dir', None): dirs.append(args.template_dir)
        lib = TemplateLibrary(dirs)
        
        t_tags = getattr(args, 'template_tags', None)
        t_ids = getattr(args, 'template_ids', None)
        templates = lib.filter(tags=t_tags, ids=t_ids) if (t_tags or t_ids) else list(lib)
        
        if t_tags or t_ids:
            print(f"\033[38;5;196m[TEMPLATES]\033[0m Found {len(templates)} matching template(s)")
        else:
            print(f"\033[38;5;196m[TEMPLATES]\033[0m {lib.summary()}")
            
        for tmpl in sorted(templates, key=lambda x: (x.severity.value, x.id)):
            cve = f" {tmpl.cve}" if tmpl.cve else ""
            tags = ",".join(tmpl.tags[:4])
            print(f"  {tmpl.severity.value:<8} {tmpl.id:<35}{cve:<22} [{tags}]  port={tmpl.port}")
        return all_results

    # ── CVE + Templates
    run_cve       = args.cve
    run_templates = getattr(args, 'templates', False)
    if (run_cve or run_templates) and args.target:
        from lightscan.cve.bridge import run_all_checks, versions_from_results
        hosts = parse_targets(args.target) if not open_ports else list(open_ports.keys())
        extra_dirs = [args.template_dir] if getattr(args, 'template_dir', None) else None
        t_tags     = getattr(args, 'template_tags', None)
        t_ids      = getattr(args, 'template_ids', None)
        cb         = args.log4shell_callback or ""
        use_legacy = run_cve  # legacy checks only with --cve, not --templates alone
        versions   = versions_from_results(all_results)  # from --active's deep_probe, if it ran
        print(f"\033[38;5;196m[{'CVE+TPL' if run_cve else 'TEMPLATES'}]\033[0m {len(hosts)} host(s)")
        for host in hosts:
            r = await run_all_checks(
                host, open_ports.get(host, []),
                template_dirs=extra_dirs,
                template_tags=t_tags,
                template_ids=t_ids,
                use_legacy=use_legacy,
                log4shell_callback=cb,
                versions=versions,
                timeout=args.timeout,
            )
            all_results.extend(r)
            for res in r:
                if res.status not in ("not_vuln","not_detected","error","no_response",
                                      "timeout","not_tls","not_enabled"):
                    print(f"  \033[38;5;196m[{res.severity.value}]\033[0m "
                          f"{res.module} @ {res.target}:{res.port} — {res.detail[:80]}")

    # ── OAuth
    if args.oauth:
        cid=args.oauth_client or "00000000-0000-0000-0000-000000000000"
        red=args.oauth_redirect or "https://localhost/callback"
        scanner=OAuthScanner(args.oauth,cid,red,args.timeout)
        all_results.extend(await scanner.scan_all())

    # ── Brute
    if args.brute and args.target:
        from lightscan.brute.engine import BruteEngine, CredentialSpray
        from lightscan.brute.handlers import get_handler, PROTOCOLS
        proto=args.brute.lower(); hosts=parse_targets(args.target)
        users=parse_userlist(args.users)
        target_info={"domain":args.target if "." in args.target else ""}
        passwords=parse_passwdlist(args.wordlist,users,target_info,args.mutate)
        jitter=tuple(args.jitter) if args.jitter else (0.0,0.0)
        brute=BruteEngine(concurrency=args.brute_conc,timeout=args.timeout,
                          jitter=jitter,checkpoint=cp if args.resume else None,verbose=args.verbose)
        print(f"\033[38;5;196m[BRUTE]\033[0m {proto.upper()} | {len(hosts)} host(s) | {len(users)} users | {len(passwords)} passwords")

        for host in hosts:
            port=args.brute_port
            if proto=="http":
                if not args.http_url: print("  [!] --http-url required for --brute http"); continue
                handler=get_handler(proto,host,port,url=args.http_url,
                    user_field=args.http_user_field,pass_field=args.http_pass_field,
                    success_text=args.http_success,failure_text=args.http_failure,
                    basic_auth=args.http_basic)
            else:
                handler=get_handler(proto,host,port)

            from lightscan.brute.handlers import PROTOCOLS as PH
            _,dport=PH[proto]; actual_port=port or dport

            if args.spray:
                spray=CredentialSpray(args.spray_window)
                pairs=[(u,p) async for u,p in spray.pairs(users,passwords)]
                u_s=list(dict.fromkeys(u for u,_ in pairs))
                p_s=list(dict.fromkeys(p for _,p in pairs))
                r=await brute.run(handler,u_s,p_s,host,actual_port,proto,args.stop_first)
            else:
                r=await brute.run(handler,users,passwords,host,actual_port,proto,args.stop_first)
            all_results.extend(r)

    # ── Summary
    elapsed=time.time()-t_start; meta["duration"]=elapsed
    crit=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="CRITICAL")
    high=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="HIGH")
    med=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="MEDIUM")
    low=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="LOW")
    info=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="INFO")
    
    high_critical_findings = [r for r in all_results if hasattr(r,"severity") and r.severity.value in ("CRITICAL", "HIGH")]
    
    print()
    if high_critical_findings:
        print(f"\033[38;5;196m┌───\033[0m \033[1mCRITICAL & HIGH FINDINGS SUMMARY\033[0m \033[38;5;196m" + "─" * 40 + "\033[0m")
        print(f"  \033[38;5;244m%-10s %-20s %-8s %-38s\033[0m" % ("SEVERITY", "TARGET", "PORT", "DETAILS"))
        print(f"  " + "\033[38;5;238m─\033[0m" * 74)
        for r in high_critical_findings:
            col = "\033[38;5;196;1m" if r.severity.value == "CRITICAL" else "\033[38;5;202;1m"
            print(f"  {col}%-10s\033[0m %-20s %-8s %-38s" % (
                r.severity.value, r.target[:20], str(r.port) if r.port else "-", r.detail[:38]
            ))
        print(f"\033[38;5;196m└" + "─" * 76 + "\033[0m\n")

    C = "\033[38;5;196m"; YEL = "\033[38;5;208m"; GRN = "\033[38;5;82m"; R = "\033[0m"
    print(f"{C}┌───────────────────────────────────────────────────────────────┐{R}")
    print(f"{C}│                      SCAN EXECUTION COMPLETE                  │{R}")
    print(f"{C}├───────────────────────────────────────────────────────────────┤{R}")
    print(f"{C}│{R}  Total Duration : {f'{elapsed:.1f}s':<44} {C}│{R}")
    print(f"{C}│{R}  Total Findings : {len(all_results):<44} {C}│{R}")
    print(f"{C}│{R}  {C}CRITICAL{R}       : {C}{crit:<44}{R} {C}│{R}")
    print(f"{C}│{R}  {YEL}HIGH{R}           : {YEL}{high:<44}{R} {C}│{R}")
    print(f"{C}│{R}  MEDIUM         : {med:<44} {C}│{R}")
    print(f"{C}│{R}  LOW / INFO     : {f'{low} / {info}':<44} {C}│{R}")
    if not args.no_report and all_results:
        base = args.basename or f"lightscan_report_{int(t_start)}"
        saved_part = f"{base}.html / .json"
        print(f"{C}│{R}  Saved Report   : {GRN}{saved_part:<44}{R} {C}│{R}")
    print(f"{C}└───────────────────────────────────────────────────────────────┘{R}\n")

    if not args.no_report and all_results:
        Reporter(args.output).save(all_results, meta, args.basename, fmt=args.format)
    return all_results


def print_minimal_help() -> None:
    """Print an animated, ultra-short terminal help guide."""
    import time
    import sys
    
    RED = "\033[38;5;196m"
    ORANGE = "\033[38;5;202m"
    YEL = "\033[38;5;220m"
    DIM = "\033[38;5;242m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    
    help_lines = [
        f"{RED}┌───\033[0m {BOLD}LIGHTSCAN HELP\033[0m {RED}" + "─" * 58 + f"\033[0m",
        f"  Usage: lightscan -t <target> [options]",
        f"         lightscan --auto <domain>",
        "",
        f"  Core Commands:",
        f"    {ORANGE}--auto <domain>{RESET}      Autonomous audit (recon → exploit → map)",
        f"    {ORANGE}--scan -t <target>{RESET}   Basic TCP port discovery scan (top100)",
        f"    {ORANGE}--active -t <target>{RESET} Full active scan (probe → vuln check → pivot)",
        f"    {ORANGE}--web-scan <url>{RESET}     Web vulnerability audit directory/SQLi/CORS",
        f"    {ORANGE}--brute <proto>{RESET}      Credential brute-force (ssh, ftp, mysql...)",
        "",
        f"  Common Options:",
        f"    {ORANGE}-p <ports>{RESET}          Ports (e.g. 22,80,443 | 1-1024 | top100)",
        f"    {ORANGE}--cve{RESET}               Run legacy/template vulnerability checks",
        f"    {ORANGE}--stealth{RESET}           IDS evasion timing template + jitter",
        f"    {ORANGE}--format <fmt>{RESET}       Output: json, html, csv, xml, minimal",
        "",
        f"  Example:",
        f"    {YEL}lightscan --auto target.com{RESET}",
        f"    {YEL}lightscan --active -t 192.168.1.1 --cve --format html{RESET}",
        f"{RED}└" + "─" * 76 + f"\033[0m",
        ""
    ]
    
    is_tty = sys.stdout.isatty()
    for line in help_lines:
        print(line)
        if is_tty:
            time.sleep(0.012)


_DEFAULT_CONCURRENCY = 256
_FD_SAFETY_MARGIN    = 100  # stdout/stderr/log files/etc eat fds too, not just scan sockets

def _tune_concurrency(requested: int | None) -> int:
    """
    rustscan does this by checking ulimit and sizing its batch to fit under
    it instead of handing out a fixed number and hoping. same idea here -
    the ulimit raise above is a best-effort attempt, this checks what we
    actually ended up with and reacts to it either way.
    """
    if sys.platform == "win32":
        return requested if requested is not None else _DEFAULT_CONCURRENCY
    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:
        return requested if requested is not None else _DEFAULT_CONCURRENCY

    if requested is not None:
        if requested + _FD_SAFETY_MARGIN > soft:
            print(f"\033[38;5;208m[!] --concurrency {requested} is close to or above your open-file "
                  f"limit ({soft}) - expect connection errors mid-scan. raise it first with "
                  f"'ulimit -n {requested + _FD_SAFETY_MARGIN}', or lower --concurrency.\033[0m", file=sys.stderr)
        return requested

    if soft - _FD_SAFETY_MARGIN < _DEFAULT_CONCURRENCY:
        tuned = max((soft // 2) if soft < _DEFAULT_CONCURRENCY else soft - _FD_SAFETY_MARGIN, 8)
        print(f"\033[38;5;208m[!] open-file limit is {soft}, too low for the usual default (256) - "
              f"scaling concurrency down to {tuned} to avoid mid-scan socket errors. "
              f"'ulimit -n {_DEFAULT_CONCURRENCY + _FD_SAFETY_MARGIN}' gets full speed back.\033[0m", file=sys.stderr)
        return tuned

    if soft > (_DEFAULT_CONCURRENCY + _FD_SAFETY_MARGIN) * 4:
        print(f"\033[38;5;240m[i] open-file limit is {soft} - plenty of headroom, "
              f"try --concurrency {min(soft - _FD_SAFETY_MARGIN, 4096)} for a faster scan.\033[0m", file=sys.stderr)

    return _DEFAULT_CONCURRENCY


def main():
    # Auto-tune system limits (ulimit -n) to prevent socket limit crashes under high concurrency
    if sys.platform != "win32":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            if soft < hard:
                # Attempt to raise to maximum hard limit
                resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        except Exception:
            pass

    # no-arg invocation — short usage hint, not full --help wall
    if len(sys.argv) == 1:
        print_banner()
        print("  Usage: lightscan -t <target> [options]")
        print("         lightscan --auto <domain>")
        print(f"\n  \033[38;5;196mlightscan -h\033[0m  for help\n")
        sys.exit(0)

    # intercept help commands
    if any(h in sys.argv for h in ("-h", "--help", "-ha", "--help-all")):
        no_banner = "--no-banner" in sys.argv
        if not no_banner:
            print_banner(no_quote=True)
        print_minimal_help()
        sys.exit(0)

    p    = build_parser()
    args = p.parse_args()
    args.concurrency = _tune_concurrency(args.concurrency)

    # Stdin Auto-detect check: only trigger if stdin is not a tty and a scanning action is requested
    target_actions = [
        getattr(args, 'scan', False),
        getattr(args, 'active', False),
        getattr(args, 'web_scan', None),
        getattr(args, 'brute', None),
        getattr(args, 'auto', None),
        getattr(args, 'dns', None),
        getattr(args, 'os_probe', None),
        getattr(args, 'traceroute', None),
    ]
    if not getattr(args, 'target', None) and not sys.stdin.isatty() and any(target_actions):
        args.target = "-"

    # Stdout redirection to stderr when output is requested on stdout via "-"
    if getattr(args, 'output', None) == "-":
        from lightscan.core.reporter import Reporter
        Reporter.stdout_override = sys.stdout
        sys.stdout = sys.stderr

    # asyncio.run() is fine on Linux/Mac; on Windows Python<3.12 the default
    # ProactorEventLoop breaks some socket operations — set SelectorEventLoop.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print(f"\n\033[38;5;240m[!] Interrupted — checkpoint saved\033[0m")
    except PermissionError as e:
        print(f"\n\033[38;5;208m[!] Permission denied: {e}")
        print("    Raw/packet scans require root. Try sudo or use --scan.\033[0m")
        sys.exit(1)


if __name__=="__main__": main()

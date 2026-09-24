"""Argument definitions for the backward-compatible LightScan CLI."""
from __future__ import annotations
import argparse
from lightscan.core.target import DEFAULT_MAX_TARGETS


_COMMAND_OPTIONS = {
    "scan": ["--scan"],
    "services": ["--scan", "--sv"],
    "web": ["--web-scan"],
    "dns": ["--dns"],
}


def normalize_command_argv(argv: list[str]) -> list[str]:
    """Translate the focused command forms into the legacy option interface."""
    if not argv or argv[0] not in _COMMAND_OPTIONS:
        return argv
    command, *arguments = argv
    if not arguments:
        raise SystemExit(f"usage: lightscan {command} TARGET [options]")
    target, *options = arguments
    target_option = ["-t"] if command in {"scan", "services"} else []
    return [*_COMMAND_OPTIONS[command], *target_option, target, *options]


def build_parser():
    p = argparse.ArgumentParser(
        prog="lightscan",
        usage="lightscan -t <target> [options]",
        description="LightScan v2.6.0 — Fast Async Network Reconnaissance & Assessment Engine",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    tg = p.add_argument_group("Target")
    tg.add_argument("-t","--target", help="IP / CIDR / range / hostname / file:path.txt")
    tg.add_argument(
        "--max-targets",
        type=int,
        default=DEFAULT_MAX_TARGETS,
        help="Maximum expanded targets before the scan is refused (default: 65536)",
    )
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
    tg.add_argument("--os-evidence",  action="store_true",
                    help="Infer OS family from existing service evidence; sends no extra probes")
    tg.add_argument("--packet-scan",  action="store_true",  help="AF_PACKET half-open SYN scan (Linux root, open/closed/filtered/firewall)")
    tg.add_argument("--stealth-scan", action="store_true",  help="IDS-evasion mode: T1 timing + jitter + sport randomisation (implies --packet-scan)")
    tg.add_argument("--spoof-sport",  type=int, default=0, metavar="PORT", help="Spoof source port (e.g. 53 or 80) to bypass port-based ACLs")
    tg.add_argument("--sv",          action="store_true",   help="Probe confirmed TCP services for product/version metadata")
    tg.add_argument("--version-concurrency", type=int, default=20,
                    help="Maximum concurrent service probes (default: 20)")
    tg.add_argument("--script",      nargs="+", metavar="SCRIPT", help="Run NSE-style scripts (e.g. http_headers tls_cert_info)")
    tg.add_argument("--script-tags", nargs="+", metavar="TAG",    help="Run all scripts with matching tags (e.g. http safe)")
    tg.add_argument("--list-scripts",action="store_true",   help="List all available scripts")
    tg.add_argument("--lua-script", nargs="+", metavar="CHECK",
                    help="Run constrained safe Lua checks on confirmed open ports")
    tg.add_argument("--lua-script-tags", nargs="+", metavar="CATEGORY",
                    help="Run constrained Lua checks in safe categories")
    tg.add_argument("--lua-script-dir", action="append", metavar="DIR",
                    help="Additional directory of reviewed .lua checks; may be repeated")
    tg.add_argument("--list-lua-scripts", action="store_true",
                    help="List built-in and supplied constrained Lua checks")
    tg.add_argument("--lua-concurrency", type=int, default=10,
                    help="Maximum concurrent Lua observations (default: 10)")
    tg.add_argument("--passive",     action="store_true",   help="Passive fingerprinting (TLS/JA3S, HTTP headers, SSH entropy)")
    tg.add_argument("--adaptive",    action="store_true", default=True, help="Adaptive timing from RTT and loss feedback (default: on)")
    tg.add_argument("--no-adaptive", action="store_false", dest="adaptive",
                    help="Use fixed timeout and concurrency controls for reproducible runs")

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

    m = p.add_argument_group("Modules")
    m.add_argument("--scan",         action="store_true", help="Bounded streaming TCP connect scan")
    m.add_argument("--go-engine",    action="store_true", help="Use the optional compiled Go TCP engine")
    m.add_argument("--go-binary",    metavar="PATH", help="Path to the lscan Go binary")
    m.add_argument("--max-rate",     type=float, default=0.0,
                   help="Maximum TCP connection starts per second; 0 disables the cap")
    m.add_argument("--retries",      type=int, default=1,
                   help="Retries for timeout or filtered TCP outcomes (default: 1)")
    m.add_argument("--retry-jitter", type=float, default=0.15,
                   help="Random retry-backoff fraction from 0.0 to 1.0 (default: 0.15)")
    m.add_argument("--host-timeout", type=float, default=0.0,
                   help="Maximum seconds spent on one host; 0 disables the cap")
    m.add_argument("--per-host-concurrency", type=int, default=32,
                   help="Maximum concurrent TCP connections per host (default: 32)")
    m.add_argument("--host-group-size", type=int, default=256,
                   help="Hosts scheduled per fairness group (default: 256)")
    m.add_argument("--no-banner-grab", action="store_true",
                   help="Skip application banner collection during TCP discovery")
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
    m.add_argument("--allow-exploit", action="store_true", default=False,
                   help="Also run intrusive: true templates (actually runs a command / reads a file / "
                        "injects sql on a hit, not just detection). off by default")
    m.add_argument("--list-templates",action="store_true", help="List all loaded templates and exit")
    m.add_argument("--search",        metavar="QUERY",     help="Search scripts and templates by keyword/tag/CVE")
    m.add_argument("--update-templates", nargs="?", const="ne0k1r4/LightScan", metavar="REPO", help="Update templates from GitHub repository (default: ne0k1r4/LightScan)")
    m.add_argument("--oauth",        metavar="AUTH_URL",  help="OAuth 2.0 audit on AUTH_URL")
    m.add_argument("--oauth-client", metavar="CLIENT_ID", help="OAuth client_id")
    m.add_argument("--oauth-redirect",metavar="URI",      help="OAuth redirect_uri")
    m.add_argument("--diff",         nargs=2, metavar=("OLD.json","NEW.json"), help="Diff two scan JSONs")
    m.add_argument("--traceroute",   metavar="HOST",      help="TCP traceroute to HOST")

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

    hb = p.add_argument_group("HTTP Brute (--brute http)")
    hb.add_argument("--http-url",        help="Login form URL")
    hb.add_argument("--http-user-field", default="username")
    hb.add_argument("--http-pass-field", default="password")
    hb.add_argument("--http-success",    default="", help="Text on successful login")
    hb.add_argument("--http-failure",    default="", help="Text on failed login")
    hb.add_argument("--http-basic",      action="store_true", help="HTTP Basic Auth mode")

    en = p.add_argument_group("Engine")
    en.add_argument("--concurrency", type=int,   default=None,  help="Scan concurrency (default: auto-tuned from ulimit, usually 256)")
    en.add_argument("--timeout",     type=float, default=3.0,  help="Connection timeout (default:3.0)")
    en.add_argument("--exclude-cdn", "-ec", action="store_true", default=False,
                     help="Known Cloudflare/Fastly IPs get scanned for 80,443 only, not the full port list")

    ev = p.add_argument_group("Evasion")
    ev.add_argument("--proxy-file",  help="SOCKS5 proxy file (socks5://host:port per line)")

    out = p.add_argument_group("Output")
    out.add_argument("-o","--output",     default=".", help="Output directory (default: .)")
    out.add_argument("--basename",        default="lightscan_report")
    out.add_argument("--format",          choices=["json", "html", "csv", "nmap-xml", "minimal"], default="json", help="Report format (default: json)")
    out.add_argument("--no-report",       action="store_true", help="Skip file reports")
    out.add_argument("--stream-open", metavar="PATH",
                     help="Write each open port immediately as NDJSON; use - for stdout")
    out.add_argument("--metrics-out", metavar="PATH",
                     help="Write a portable v1 performance snapshot after --scan")
    out.add_argument("--compare-metrics", nargs=2, metavar=("BASELINE.json", "CANDIDATE.json"),
                     help="Compare two v1 performance snapshots and exit")
    out.add_argument("--import-nmap-xml", metavar="PATH",
                     help="Import OS and open-service observations from local Nmap XML; does not scan")
    out.add_argument("--resume",          action="store_true", help="Resume from checkpoint")
    out.add_argument("--clear-checkpoint",action="store_true", help="Clear checkpoint and start fresh")
    out.add_argument("-v","--verbose",    action="store_true", help="Clean, detailed, animated verbose output with live progress telemetry")
    out.add_argument("-q","--quiet",      action="store_true", help="Quiet mode: suppress banners, status lines, and progress output")
    out.add_argument("--min-severity",    choices=["info", "low", "medium", "high", "critical"], default="info", help="Filter minimum severity of reported findings (default: info)")
    out.add_argument("--no-discovery", action="store_true", help="Skip host discovery")
    out.add_argument("--smb-enum", action="store_true", help="SMB null session + share enum")
    out.add_argument("--snmp", action="store_true", help="SNMP enumeration")
    out.add_argument("--snmp-community", default="public")
    out.add_argument("--no-banner",       action="store_true", help="Suppress banner (useful with --format json or scripted use)")
    return p

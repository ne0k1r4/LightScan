# LightScan v2.0 — PHANTOM

> Autonomous red-team reconnaissance and attack framework.  
> Point it at a domain. Walk away. Come back to a compromise map.

Built in pure Python — no heavy dependencies, no brittle wrappers around third-party tools. Just fast, async, protocol-level code that does what a real attacker would do, step by step, without waiting for you to tell it what's next.

---

## What it does

LightScan started as a port scanner. It's grown into something closer to a junior red-teamer running on autopilot — one that knows what to do with an open Redis port, can recognize a Domain Controller from its TCP fingerprint, and chains findings together into actionable attack paths before you've finished your coffee.

**The short version:**

- Feed it a domain and it will enumerate subdomains, resolve IPs, scan ports, identify vulnerable services, validate them with real PoC payloads, brute-force credentials on anything that looks brute-able, detect Active Directory, and hand you a JSON compromise map with ordered attack chains.
- Feed it a target IP and it will do the same thing from the network layer up.
- Or use individual modules — port scanner, web scanner, brute-forcer, CVE checker — exactly like you would any other tool.

---

## Feature overview

### Autonomous pipeline (`--auto`)
The main event. Give it a domain name and it runs a full 10-stage red-team engagement without further input:

```
DNS/CT logs → subdomain resolution → host discovery → port scan
→ service fingerprinting → CVE checks → exploit chain analysis
→ credential attacks → Active Directory detection → web deep-scan
→ compromise map (JSON + terminal report)
```

Each stage feeds its findings into the next. If it finds Redis open on a host, it validates unauthenticated access and immediately builds a webshell RCE chain. If it finds Kerberos + LDAP on the same host, it marks it as a Domain Controller candidate and prints the DCSync path. If it cracks credentials anywhere, those get forwarded into privilege escalation chains automatically.

### Active scan (`--active`)
Four-phase active recon on any target range:
1. **Host discovery** — ICMP raw socket ping, ARP table lookup for LAN targets, TCP-connect fallback when root isn't available
2. **Port scan** — async TCP across configurable intensity levels (9 ports to all ports)
3. **Deep service probing** — protocol-specific payloads per port, version extraction from banners
4. **Vuln validation + pivot map** — real PoC probes against FTP, Redis, MongoDB, SMBv1, LDAP, Telnet, and a set of HTTP exposure checks

### Port scanning
Async TCP connect, SYN half-open (Scapy), raw epoll-based SYN scanner (nmap speed, no Scapy), AF_PACKET stealth mode, UDP, IPv6/dual-stack. Timing templates T0–T5.

### Service version detection (`--sv`)
Equivalent to `nmap -sV`. Protocol probes → banner capture → regex fingerprint DB with 500+ signatures → confidence-scored output.

### OS detection
Two layers: passive from SYN-ACK TTL/window/options (zero extra packets), and active T2–T7 multi-probe fingerprinting with a 120+ signature database.

### Web scanner (`--web-scan`)
Full OWASP Top 10 coverage: directory brute, tech fingerprinting, SQLi, XSS, SSRF, LFI, open redirect, CORS misconfiguration, default credentials, JWT `alg:none` downgrade, secret file exposure, API endpoint enumeration.

### CVE / Template engine (`--cve`)
Nuclei-style YAML templates. 60+ templates across CVE, network, auth, misconfiguration, and exposed service categories. Legacy PoC checkers for EternalBlue, Log4Shell, Spring4Shell, Heartbleed, ShellShock, BlueKeep, and more.

### NSE-style scripts (`--script`)
Built-in scripts: TLS versions, cipher enumeration, cert info, SSH algorithms, SSH host key, HTTP headers, HTTP methods, HTTP auth detection, SMB OS discovery, SMB signing, DNS zone transfer, DNS recursion test.

### Brute force (`--brute`)
12 protocols: SSH, FTP, Telnet, SMB, RDP, MySQL, PostgreSQL, MSSQL, HTTP (form + Basic Auth), LDAP, VNC, MongoDB. Smart mutation engine, credential spray mode with lockout protection, jitter controls.

### OAuth 2.0 audit (`--oauth`)
Token leakage checks, open redirect in redirect_uri, CSRF state validation, PKCE bypass attempts, implicit flow detection, scope enumeration.

### Evasion
Timing templates, decoy IP injection, IP packet fragmentation, source port spoofing, port scan order randomization, stealth mode (T1 + jitter + reduced concurrency).

---

## Installation

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan

# Core framework — zero required dependencies
pip install -e .

# Optional: full brute-force + NTLM + Scapy SYN scanning
pip install -r requirements.txt
```

Python 3.10+ recommended. Root/sudo required for raw socket modes (SYN scan, ICMP ping, packet scan). Everything else works as a normal user.

---

## Usage

### Autonomous mode — the main feature
```bash
# Full autonomous engagement: subdomains → compromise map
lightscan --auto target.com

# With strict scope enforcement (blocks out-of-scope probes)
lightscan --auto target.com --scope 10.0.0.0/8 192.168.1.0/24

# Stealth: T1 timing, jitter, reduced concurrency
lightscan --auto target.com --stealth

# Control which stages run
lightscan --auto target.com --skip-web --skip-brute

# Intensity 1 (9 ports, quiet) to 5 (all ports, noisy)
lightscan --auto target.com --intensity 2
```

### Active scan
```bash
# Active red-team scan on a subnet
lightscan --active -t 192.168.1.0/24

# With scope, stealth, and intensity control
lightscan --active -t 10.0.0.0/24 --scope 10.0.0.0/24 --stealth --intensity 3

# Verbose — prints every open port as found
lightscan --active -t 10.0.0.1 --intensity 5 -v
```

### Port scanning
```bash
# Fast async TCP scan
lightscan --scan -t 10.0.0.1 -p top100

# SYN half-open (root + Scapy)
lightscan --scan -t 10.0.0.0/24 --syn -p 1-1024

# Raw epoll SYN scanner, nmap speed (root, no Scapy)
lightscan --scan -t 10.0.0.1 --raw -p top1000 -T T4

# Stealth packet scan with source port spoofing
lightscan --scan -t 10.0.0.1 --stealth-scan --spoof-sport 53

# UDP
lightscan --scan -t 10.0.0.1 --udp

# With service version detection and CVE checks
lightscan --scan -t 10.0.0.1 --sv --cve
```

### Web scanning
```bash
# Full OWASP Top 10 scan
lightscan --web-scan http://target.local

# Specific checks only
lightscan --web-scan http://target.local --web-checks sqli xss cors secrets

# With custom wordlist for directory brute
lightscan --web-scan http://target.local --web-wordlist /path/to/wordlist.txt
```

### Brute force
```bash
# SSH with smart password mutation
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W common --mutate

# Credential spray across all users (1 password per window — lockout safe)
lightscan --brute ssh -t 10.0.0.1 -U file:users.txt -W file:passwords.txt --spray

# HTTP form brute
lightscan --brute http -t 10.0.0.1 --http-url http://10.0.0.1/login \
  --http-user-field username --http-pass-field password \
  --http-success "Welcome" -U admin -W common

# With jitter to avoid detection
lightscan --brute rdp -t 10.0.0.1 -U administrator -W common --jitter 1.5 4.0
```

### Other modules
```bash
# DNS enumeration (subdomains, AXFR, crt.sh)
lightscan --dns target.com

# CVE template checks on open ports
lightscan --scan -t 10.0.0.1 --cve

# Specific CVE
lightscan --scan -t 10.0.0.1 --cve-list eternalblue log4shell

# NSE-style scripts
lightscan --scan -t 10.0.0.1 -p 22,443 --script ssh_algorithms tls_cert_info

# OS fingerprinting
lightscan --scan -t 10.0.0.1 --os-v2

# RDP probe
lightscan --rdp-probe 10.0.0.1

# TCP traceroute
lightscan --traceroute target.com

# Diff two scan results
lightscan --diff old_scan.json new_scan.json

# OAuth 2.0 audit
lightscan --oauth https://login.target.com/oauth/authorize --oauth-client CLIENT_ID
```

---

## Output

Every scan produces three files in the output directory (default: current directory):

- `lightscan_report.json` — full machine-readable results
- `lightscan_report.md` — grouped markdown report with severity headers
- `lightscan_report.html` — styled HTML report with color-coded findings

For `--auto` mode, an additional `compromise_map_<domain>.json` is written with the full attack graph.

```bash
# Custom output directory and base name
lightscan --auto target.com -o /tmp/engagement --basename target_recon
```

---

## Project structure

```
lightscan/
├── cli.py                  # Entry point, argument parsing, module orchestration
├── banner.py               # Startup banner
├── core/
│   ├── engine.py           # Async task runner, ScanResult, Severity types
│   ├── reporter.py         # JSON / Markdown / HTML report generation
│   ├── checkpoint.py       # Resume support for interrupted scans
│   └── target.py           # Target parsing: IPs, CIDRs, ranges, hostnames
├── scan/
│   ├── active.py           # Active red-team engine (discovery → vulns → pivots)
│   ├── orchestrator.py     # Autonomous 10-stage engagement pipeline
│   ├── exploit_chain.py    # Context-aware exploit chain builder
│   ├── portscan.py         # Async TCP connect scanner
│   ├── rawscan.py          # epoll-based raw SYN scanner
│   ├── syn.py              # Scapy SYN scanner with OS passive fingerprinting
│   ├── packetscan.py       # AF_PACKET stealth scanner
│   ├── udp.py              # UDP scanner with ICMP classification
│   ├── sversion.py         # Service version detection (nmap -sV equivalent)
│   ├── passive.py          # Passive fingerprinting: TLS/JA3S, HTTP, SSH entropy
│   ├── os_detect.py        # Active T2-T7 OS fingerprinting
│   ├── osdb.py             # OS fingerprint database v2 (120+ signatures)
│   ├── scripts.py          # NSE-style script engine + built-in scripts
│   ├── dns.py              # DNS enumeration, AXFR, subdomain brute, crt.sh
│   ├── traceroute.py       # TCP traceroute
│   ├── ipv6scan.py         # IPv6 / dual-stack scanning
│   ├── adaptive.py         # Adaptive timing based on RTT/loss
│   └── diff.py             # Scan result diff/comparison
├── brute/
│   ├── engine.py           # Brute force engine + credential spray
│   ├── mutation.py         # Smart password mutation engine
│   └── handlers/           # Protocol handlers: SSH, FTP, RDP, SMB, HTTP, etc.
├── cve/
│   ├── checker.py          # PoC CVE checkers (EternalBlue, Log4Shell, etc.)
│   ├── template_engine.py  # Nuclei-style YAML template runner
│   ├── bridge.py           # Unified checker interface
│   └── oauth.py            # OAuth 2.0 security audit
├── web/
│   └── scanner.py          # Full web application vulnerability scanner
├── evasion/
│   └── __init__.py         # Timing templates, decoys, fragmentation helpers
└── templates/
    ├── cve/                # 24 CVE detection templates
    ├── network/            # Network exposure templates
    ├── auth/               # Auth bypass / default credential templates
    ├── misconfig/          # Misconfiguration templates
    └── exposed/            # Exposed service templates
```

---

## Evasion reference

| Flag | Effect |
|------|--------|
| `-T T0` to `-T T5` | Timing: T0 paranoid (15s between probes) to T5 insane (0.001s) |
| `--stealth` | T1 timing + 1–3s jitter + reduced concurrency (auto mode) |
| `--stealth-scan` | AF_PACKET scan + T1 + source port randomization |
| `--decoy N` | Inject N random decoy IPs alongside real probes |
| `--fragment` | Fragment IP packets to evade stateless IDS |
| `--source-port PORT` | Fix source port (e.g. `--source-port 53` to bypass ACLs) |
| `--spoof-sport PORT` | Spoof source port in packet-level scans |
| `--no-randomize` | Disable port order randomization (sequential scanning) |

---

## Scope enforcement

When running `--auto` or `--active`, pass `--scope` to define allowed targets. Anything outside the defined CIDRs or domains is silently skipped — no accidental probes outside your engagement boundary.

```bash
lightscan --auto target.com --scope 10.0.0.0/8 target.com *.target.com
```

---

## Resuming interrupted scans

Large scans write a checkpoint file automatically. Resume with:

```bash
lightscan --scan -t 10.0.0.0/8 -p top1000 --resume
```

---

## Legal notice

This tool is built for authorized penetration testing, red team engagements, CTF competitions, and security research on systems you own or have explicit written permission to test. Running it against systems without authorization is illegal in most jurisdictions. The author takes no responsibility for how this is used.

If you're on an authorized engagement — have fun.

---

*Built by [Light](https://github.com/ne0k1r4) — feedback and pull requests welcome.*

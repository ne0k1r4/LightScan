# LightScan v2.0 — PHANTOM

Autonomous red-team recon and attack framework. Point it at a domain, walk away, come back to a compromise map.

Pure Python. Zero hard dependencies. Runs at nmap speed.

---

## Install

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan
pip install -e .                   # core — stdlib only
pip install -r requirements.txt    # full: brute force, SYN scan, YAML templates
```

Python 3.10+. Root required for raw socket modes (SYN scan, ICMP ping).

---

## Quick start

```bash
# Fully autonomous — subdomain enum → port scan → exploit chains → DC map
lightscan --auto target.com

# Active red-team scan on a subnet
lightscan --active -t 192.168.1.0/24 --intensity 3

# Stay in scope, stay quiet
lightscan --auto target.com --scope 10.0.0.0/8 --stealth

# Classic port scan + service version + CVE checks
lightscan --scan -t 10.0.0.1 -p top1000 --sv --cve

# Web app scan
lightscan --web-scan http://target.local

# Brute force SSH with smart mutation
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W common --mutate

# DNS enumeration
lightscan --dns target.com
```

---

## What --auto does

10 stages, fully chained, no prompts:

```
crt.sh + DNS brute → resolve IPs → host discovery → port scan
→ service fingerprinting → CVE validation → exploit chain build
→ credential brute → DC/AD detection → web deep-scan
→ compromise_map_<domain>.json
```

Findings feed forward automatically. Redis unauth → webshell chain. Kerberos + LDAP → DCSync path. Cracked creds → passed into the next stage.

---

## Key flags

| Flag | What it does |
|------|-------------|
| `--auto DOMAIN` | Full autonomous engagement |
| `--active -t TARGET` | 4-phase active scan (discover → probe → vuln → pivot) |
| `--intensity 1-5` | Port breadth: 1 = 9 ports, 5 = all ports |
| `--scope CIDR` | Hard scope enforcement — nothing outside this gets touched |
| `--stealth` | T1 timing + jitter + reduced concurrency |
| `--sv` | Service version detection (nmap -sV equivalent) |
| `--cve` | CVE + YAML template checks |
| `--brute PROTO` | Brute force: ssh ftp rdp smb mysql postgres mssql http ldap vnc |
| `--web-scan URL` | OWASP Top 10 web scanner |
| `--os-v2` | OS fingerprinting (120+ signatures) |
| `--script NAMES` | NSE-style scripts (tls_cert_info, ssh_algorithms, smb_signing…) |
| `--syn` | SYN half-open scan (root + Scapy) |
| `--raw` | epoll SYN scan — nmap speed, no Scapy |
| `-T T0-T5` | Timing templates (T0 paranoid → T5 insane) |

---

## Output

Every scan writes three files (default: current directory):

- `lightscan_report.json`
- `lightscan_report.md`
- `lightscan_report.html`

`--auto` also writes `compromise_map_<domain>.json` — a structured attack graph with ordered exploit chains per host.

---

## Project layout

```
lightscan/
├── cli.py                 # entry point
├── core/                  # engine, reporter, checkpoint, target parser
├── scan/
│   ├── orchestrator.py    # autonomous 10-stage pipeline
│   ├── active.py          # active red-team engine
│   ├── exploit_chain.py   # exploit chain builder
│   ├── portscan.py        # async TCP scanner
│   ├── rawscan.py         # epoll SYN scanner
│   ├── sversion.py        # service version detection
│   ├── scripts.py         # NSE-style scripts
│   └── ...                # os_detect, dns, passive, udp, ipv6, traceroute
├── brute/                 # brute force engine + 12 protocol handlers
├── cve/                   # CVE checkers + YAML template engine + OAuth audit
├── web/                   # web application scanner
└── templates/             # 60+ YAML detection templates
```

---

## Legal

For authorized penetration testing, red team engagements, CTF, and security research only. Don't run this against systems you don't own or have explicit written permission to test.

---

*Built by [Light](https://github.com/ne0k1r4)*

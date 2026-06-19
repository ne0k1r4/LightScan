# LightScan v2.0 — PHANTOM

> Autonomous red-team recon and attack framework.  
> Point it at a domain. Walk away. Come back to a compromise map.

Pure Python core · Zero hard dependencies · Go companion binary for 10k+ concurrent scans

[![Languages](https://img.shields.io/badge/output-EN%20%7C%20ZH%20%7C%20RU%20%7C%20AR%20%7C%20ES-blue)](https://github.com/ne0k1r4/LightScan)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Go](https://img.shields.io/badge/go-1.21%2B-00ADD8)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Install

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan
pip install -e .                   # core — stdlib only
pip install -e ".[full]"           # or: pip install -r requirements.txt
make go                            # optional: build Go scanner binary
```

Python 3.10+. Root required for raw socket modes (SYN scan, ICMP ping).

---

## Language

Output language is auto-detected from `$LANG`. Override with `--lang`:

```bash
lightscan --lang zh --auto target.com   # Chinese
lightscan --lang ru --scan -t 10.0.0.1  # Russian
lightscan --lang ar --auto target.com   # Arabic
lightscan --lang es --brute ssh ...     # Spanish
```

Supported: `en` `zh` `ru` `ar` `es`

---

## Quick start

```bash
# Fully autonomous — subdomain enum → port scan → exploit chains → DC map
lightscan --auto target.com

# Stay in scope, stay quiet
lightscan --auto target.com --scope 10.0.0.0/8 --stealth

# Active red-team scan on a subnet
lightscan --active -t 192.168.1.0/24 --intensity 3

# Classic port scan + service version + CVE checks
lightscan --scan -t 10.0.0.1 -p top1000 --sv --cve

# Web app scan
lightscan --web-scan http://target.local

# Brute force SSH with smart mutation
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W common --mutate
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

Findings feed forward automatically. Redis unauth → webshell chain.  
Kerberos + LDAP → DCSync path. Cracked creds → passed into the next stage.

---

## Go scanner

For large subnet sweeps the Go binary handles 10,000+ concurrent connections
more efficiently than Python's async scanner:

```bash
make go                          # builds scanner/lscan
./scanner/lscan -t 10.0.0.0/16 -p top100 -c 5000 --json
```

The Python engine calls it automatically when `lscan` is in PATH and `--raw-go` is passed.

---

## Key flags

| Flag | What it does |
|------|-------------|
| `--auto DOMAIN` | Full autonomous engagement |
| `--active -t TARGET` | 4-phase active scan (discover → probe → vuln → pivot) |
| `--intensity 1-5` | Port breadth: 1 = 9 ports, 5 = all ports |
| `--scope CIDR` | Hard scope enforcement |
| `--stealth` | T1 timing + jitter + reduced concurrency |
| `--lang LANG` | Output language: en zh ru ar es |
| `--sv` | Service version detection |
| `--cve` | CVE + YAML template checks |
| `--brute PROTO` | Brute force: ssh ftp rdp smb mysql postgres mssql http ldap |
| `--web-scan URL` | OWASP Top 10 web scanner |
| `--syn` / `--raw` | SYN scan (Scapy / epoll) |
| `-T T0-T5` | Timing templates |

---

## Output

- `lightscan_report.json` — full results
- `lightscan_report.md` — grouped markdown
- `lightscan_report.html` — dark-themed dashboard with severity filter
- `compromise_map_<domain>.json` — attack graph (--auto only)

---

## Project layout

```
lightscan/
├── cli.py              # entry point
├── core/               # engine, reporter, checkpoint, target parser
├── scan/
│   ├── orchestrator.py # autonomous 10-stage pipeline
│   ├── active.py       # active red-team engine
│   ├── exploit_chain.py# exploit chain builder
│   ├── portscan.py     # async TCP scanner
│   ├── rawscan.py      # epoll SYN scanner
│   └── ...             # sversion, os_detect, dns, passive, udp, ipv6
├── brute/              # brute force engine + 12 protocol handlers
├── cve/                # CVE checkers + YAML templates + OAuth audit
├── web/                # web application scanner
└── templates/          # 60+ YAML detection templates
scanner/
├── main.go             # Go high-performance scanner
└── go.mod
```

---

## Legal

For authorized penetration testing, red team engagements, CTF, and security research only.  
Don't run this against systems you don't own or have explicit written permission to test.

---

*Built by [Light](https://github.com/ne0k1r4)*

## new in v2.1.0

```bash
# passive mode — zero packets
sudo lightscan --passive-mode --passive-iface eth0 --passive-time 120

# nmap-xml for metasploit
lightscan --scan -t 10.0.0.1 -p top100 --format nmap-xml

# CT log subdomain discovery
lightscan --dns target.com

# SMB enumeration
lightscan --scan -t 10.0.0.1 -p 445 --smb-enum

# SNMP enumeration
lightscan --scan -t 10.0.0.1 -p 161 --snmp

# full version detection
lightscan --scan -t 10.0.0.1 -p top100 --sv

# dual-stack IPv6 check
lightscan --scan -t target.com --dual-stack-check
```
# brute examples
# brute examples

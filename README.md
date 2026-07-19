# LightScan v2.1 — PHANTOM

> Autonomous red-team recon and attack framework.  
> Point it at a domain. Walk away. Come back to a compromise map.

Pure Python core · Zero hard dependencies · Go companion binary for 10k+ concurrent scans

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Go](https://img.shields.io/badge/go-1.21%2B-00ADD8)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Install

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan
pip install -e .                   # Core — stdlib only
pip install -e ".[full]"           # Full features (requirements.txt)
make go                            # Optional: Build fast Go scanner binary
```

Python 3.10+ required. Root privileges required for raw packet socket modes (SYN scan, ICMP ping, active OS probing).

---

## Quick Start

```bash
# Autonomous audit flow — subdomains → port discovery → exploit chains → DC compromise map
lightscan --auto target.com

# Stay in scope, run quietly (T1 timing + jitter)
lightscan --auto target.com --scope 10.0.0.0/8 --stealth

# Sn1per-style Sweep Mode (host & port discovery only, skips heavy vuln checks/brute/web stages)
lightscan --active -t 192.168.1.0/24 --mode sweep

# Sn1per-style Deep Mode (full 5-phase active red-team audit)
lightscan --active -t 192.168.1.0/24 --mode deep

# Pipe targets from stdin and output clean JSON results to stdout (ProjectDiscovery-style)
cat hosts.txt | lightscan --active --output - --format json | jq

# Port scan + service version + CVE template checks
lightscan --scan -t 10.0.0.1 -p 22,80,443,8080 --sv --cve

# Web vulnerability app scan
lightscan --web-scan http://target.local

# Brute force SSH with smart word mutation
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W common --mutate
```

---

## Key Architectural Updates

### 1. AutoRecon-style Plugin Registry
Active port validator checks are built as dynamic plugins registered via a decorator. This allows multiple modular check handlers to target the same port without colliding:
```python
@register_validator([389, 636])
async def _check_ldap_anon(host, port, timeout):
    # Anonymous LDAP bind verification logic
    ...
```

### 2. Nuclei-style Matcher DSL
Vulnerability YAML templates in `lightscan/templates/` now support complex multi-step condition matchers, part selection (headers, body, all), status code lists, and negative boolean matching:
```yaml
id: docker-api-exposed
name: Docker Daemon API Exposed
severity: critical
steps:
  - type: send
    data: /version
  - type: match
    matchers-condition: and
    matchers:
      - type: word
        words: ["ApiVersion", "Arch"]
        condition: and
        part: body
      - type: status
        status: [200]
```

### 3. Unix Pipe Friendly Target & Output Routing
* **Piped Input**: Target `-t -` (or default target value when stdin is not a TTY) reads targets line-by-line from stdin.
* **Piped Output**: Setting `--output -` prints clean final reports (JSON, minimal txt, XML, CSV) to stdout. 
* **OPSEC stderr Redirect**: When standard output redirection is active, all terminal banners, logs, spinner animations, and progress graphs are automatically redirected to `sys.stderr` to keep stdout clean.

---

## What `--auto` Does (Autonomous Mode)

10 chained stages running concurrently without prompt interruptions:
```
crt.sh + DNS brute → Resolve IPs → Host discovery → Port scan
→ Service fingerprinting → CVE matchers → Exploit chain builder
→ Credential brute-force → Active DC hunt → Web deep-scan
→ compromise_map_<domain>.json
```
Discovered findings automatically feed forward to subsequent stages. Discovered credentials on one host are immediately sprayed against others.

---

## Key CLI Controls

| Flag | What it does |
|------|-------------|
| `--auto DOMAIN` | Full autonomous recon, exploit, and pivot mapping |
| `--active -t TARGET` | Active red-team scan (discovery → probe → vuln → pivot) |
| `--mode {sweep,deep}` | Sweep (recon/port map only) or Deep (full active validation) |
| `--intensity 1-5` | Port scanning speed/depth preset |
| `--scope CIDR` | Strictly restrict target scopes (drops out-of-scope targets) |
| `--stealth` | Evasion timing + jitter + reduced worker concurrency |
| `--sv` | Deep service version probing |
| `--cve` | Run template-engine checks on discovered services |
| `--brute PROTO` | Target credential brute-forcing |
| `--web-scan URL` | OWASP Web vulnerability directory & script scanner |
| `--output -` | Dump report directly to stdout (silences console banner pollution) |
| `--format json/xml/csv` | Output reports file format |

---

## Project Layout

```
lightscan/
├── cli.py              # CLI controller & consolidated animated TUI help
├── core/               # Target parsing, report generation, async engine
├── scan/
│   ├── orchestrator.py # 10-stage autonomous chain executor
│   ├── active.py       # Plugin registry & active validation phases
│   ├── exploit_chain.py# Exploit chain generator
│   └── ...             # Portscan, dns, cdn, passive, udp, ipv6 scan
├── brute/              # Credential sprayer & brute-force handlers
├── cve/                # CVE Checker & Nuclei-style YAML template engine
├── web/                # Tech detector & web vulnerability scanner
└── templates/          # YAML PoC templates for service misconfigurations
```

---

## Legal

This tool is designed for authorized penetration testing, red team auditing, and security research. Only execute this tool against target networks where you have explicit written permission.

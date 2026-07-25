# LightScan (v2.1-PHANTOM)

An autonomous network recon and attack framework written in pure Python (zero mandatory external dependencies) with a high-performance Go companion binary for concurrent port scanning.

Point it at a domain or IP range, walk away, and return to an interactive compromise map and vulnerability dashboard.

---

## Setup & Installation

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan

# Install core framework (stdlib only, zero mandatory external packages)
pip install -e .

# Install full features (Scapy, Paramiko, BeautifulSoup for raw SYN & deep web scans)
pip install -e ".[full]"

# (Optional) Compile high-speed Go companion scanner binary
make go
```

*Note: Raw socket operations (SYN scanning, ICMP pings, active OS detection) require root privileges (`sudo`).*

---

## Quick Start & Usage Examples

### 1. Autonomous Engagement Mode (`--auto`)
Chains 10 automated phases: subdomains → DNS resolution → host discovery → port scanning → service fingerprinting → CVE checks → exploit chain building → credential brute-forcing → Active Directory hunt → deep web app audit.
```bash
# Full autonomous audit on a target domain
lightscan --auto target.com

# Autonomous mode with strict scope boundary and stealth evasion timing
lightscan --auto target.com --scope 10.0.0.0/8 --stealth
```

### 2. Active Red-Team Scanning (`--active` / `--mode`)
Runs a 5-phase active audit: discovery → port mapping → deep service probing → vulnerability validation → pivot suggestion graph.
```bash
# Fast recon sweep (host discovery + port scan only, skips deep CVE/web checks)
lightscan --active -t 192.168.1.0/24 --mode sweep

# Full 5-phase deep audit on a target network
lightscan --active -t 192.168.1.0/24 --mode deep --intensity 4
```

### 3. UNIX Piping & Script Automation (`-t -` / `--output -`)
Seamlessly pipe inputs and outputs with Unix tools (ProjectDiscovery-style). Banners and progress animations are automatically redirected to `stderr` when piping stdout.
```bash
# Feed target IPs from stdin and stream clean JSON results directly to jq
cat targets.txt | lightscan --active --output - --format json | jq '.'

# Pipe scan results in Nmap XML format for Metasploit ingestion
cat subnets.txt | lightscan --scan -p 22,80,443 --output - --format nmap-xml
```

### 4. Multi-Protocol Brute-Forcing & Credential Spraying (`--brute`)
Supports 12+ protocols: `ssh`, `ftp`, `smb`, `rdp`, `http`, `mysql`, `postgres`, `mssql`, `redis`, `mongo`, `ldap`, `vnc`, `telnet`.
```bash
# Target brute-forcing with smart wordlist mutations
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W common --mutate

# Low-and-slow credential spraying (1 pass across N users every 30 minutes)
lightscan --brute smb -t 10.0.0.0/24 -U file:users.txt -W Password1! --spray --spray-window 1800
```

### 5. Web Application Vulnerability Audit (`--web-scan`)
Scans web apps for OWASP Top 10 vulnerabilities, directory exposures, SQLi, XSS, CORS misconfigurations, JWT downgrades, and JS secret leaks.
```bash
# Full web application audit
lightscan --web-scan http://target.local

# Run specific web vulnerability checks with custom wordlist
lightscan --web-scan http://target.local --web-checks dir sqli xss cors --web-wordlist common.txt
```

---

## Core Features & Architecture

### 1. AutoRecon-Style Plugin Registry
Port-specific active validators use a dynamic `@register_validator` decorator system rather than a static dictionary. Multiple checks can bind to the same port without collisions:
```python
@register_validator([389, 636])
async def _check_ldap_anon(host, port, timeout):
    # Anonymous LDAP bind PoC validation logic
    ...
```

### 2. Nuclei-Style Matcher DSL
YAML templates in `lightscan/templates/` support multi-step HTTP/TCP probes, logical condition groups (`matchers-condition: and|or`), regex/word/status matchers, part selection (`body`, `headers`, `all`), and boolean negations (`negative: true`):
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

### 3. Evasion, OPSEC & Timing Controls
* **Timing Templates**: Preset rates from $T0$ (paranoid stealth) to $T5$ (insane high-speed).
* **IDS Evasion**: Fragment IP packets (`--fragment`), send decoy IPs (`--decoy 5`), and spoof source ports (`--source-port 53`).
* **Stealth Mode**: Includes T1 timing, 1-3 second random jitter, reduced worker concurrency, and CDN detection (`--exclude-cdn`).
* **Auto-Tuned Concurrency**: Automatically reads system `ulimit` file descriptor caps to optimize thread worker limits without socket exhaustion crashes.

### 4. Dual-Stack IPv6 & Passive Traffic Sniffing
* **IPv6 Scanning**: Dual-stack auto-resolution (`--dual-stack`), SLAAC interface address prediction from MAC addresses, and IPv6 connect scanning.
* **Passive Traffic Sniffing**: Silent network observation (`--passive`) analyzing ARP, DNS, mDNS, DHCP, NetBIOS, and TLS/JA3S headers with zero packets sent.

---

## Command Line Reference

| Category | Flag | Description |
| :--- | :--- | :--- |
| **Autonomous** | `--auto DOMAIN` | Full autonomous engagement chain (recon → exploit → map) |
| | `--active -t TARGET` | Active red-team scan (discovery → probe → vuln → pivot) |
| | `--mode {sweep,deep}` | Recon sweep (ports only) or deep 5-phase audit |
| | `--scope CIDRs` | Restrict target boundary; drop out-of-scope probes |
| **Scanning** | `-t`, `--target` | Target IP, range, CIDR, hostname, or `-` for stdin pipe |
| | `-p`, `--ports` | Port list: `22,80,443`, `1-1024`, or `top100` (default) |
| | `--sv` | Service version detection & banner grabbing |
| | `--cve` | Run CVE checkers and YAML detection templates |
| | `-6`, `--dual-stack` | Resolve and scan IPv4 and IPv6 dual-stack targets |
| **Brute Force** | `--brute PROTO` | Protocol brute-forcer (`ssh`, `smb`, `rdp`, `ftp`, `mysql`...) |
| | `-U`, `--users` | Username list or `file:users.txt` |
| | `-W`, `--wordlist` | Password list, `common`, or `file:passwords.txt` |
| | `--mutate` | Smart password mutation engine (leet, suffixes, context) |
| | `--spray` | Low-and-slow credential spraying mode |
| **Web Scan** | `--web-scan URL` | OWASP web vulnerability scanner |
| | `--web-checks` | Filter web checks (`dir`, `sqli`, `xss`, `cors`, `creds`, `jwt`) |
| **Evasion & Output**| `-T T0-T5` | Timing template ($T0$ paranoid to $T5$ insane) |
| | `--stealth` | OPSEC mode (T1 timing, jitter, low concurrency) |
| | `-o`, `--output` | Output directory or `-` for stdout streaming |
| | `--format` | Report format: `json`, `html`, `nmap-xml`, `csv`, `minimal` |

---

## Codebase Layout

```
lightscan/
├── cli.py              # CLI entrypoint & animated TUI help guide
├── banner.py           # ASCII art banner & quote generator
├── core/               # Engine orchestrator, target parsers, reporter, checkpoints
├── scan/
│   ├── orchestrator.py # 10-stage autonomous audit engine
│   ├── active.py       # Plugin registry & 5-phase active red-team scanner
│   ├── portscan.py     # High-speed async TCP scanner
│   ├── rawscan.py      # Epoll raw SYN scanner
│   └── ...             # IPv6, passive, OS detection, DNS, CDN, evasion
├── brute/              # Credential brute-force engine, mutation rules & 12+ protocol handlers
├── cve/                # CVE checkers, Nuclei-style YAML template engine & OAuth auditor
├── web/                # OWASP web application scanner & secret detector
└── templates/          # YAML detection templates for vulnerabilities & service exposures
scanner/
└── main.go             # High-performance Go companion port scanner
tests/                  # Complete test suite (100+ unit & integration test cases)
```

---

## License & Legal

LightScan is intended strictly for authorized penetration testing, red team auditing, and security research. Always obtain explicit written permission before auditing any network or system.

Licensed under the [MIT License](LICENSE).

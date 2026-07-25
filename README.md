# LightScan (v2.1-PHANTOM)

Autonomous network recon and attack framework in pure Python (stdlib core) with a Go companion binary for high-speed port scanning.

Point it at a domain or IP range → get a complete compromise map and vulnerability report.

---

## Installation

```bash
git clone https://github.com/ne0k1r4/LightScan && cd LightScan

pip install -e .           # Core engine (stdlib only)
pip install -e ".[full]"   # Optional: Scapy (raw SYN), Paramiko, BeautifulSoup
make go                    # Optional: High-speed Go port scanner
```
*Note: SYN scans, ICMP pings, and raw OS probes require `sudo`.*

---

## Quick Start

```bash
# 1. Full Autonomous Engagement (10-stage chain: recon → exploit → DC map)
lightscan --auto target.com --scope 10.0.0.0/8

# 2. Active Red-Team Audit (5-phase scan: discovery → probe → vuln → pivot)
lightscan --active -t 192.168.1.0/24 --mode deep

# 3. Fast Recon Sweep (Host discovery & open ports only)
lightscan --active -t 192.168.1.0/24 --mode sweep

# 4. UNIX Stdin / Stdout Piping (ProjectDiscovery-style clean JSON)
cat targets.txt | lightscan --active --output - --format json | jq '.'

# 5. Multi-Protocol Brute-Forcing & Smart Wordlist Mutation
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W common --mutate

# 6. Web Application Vulnerability Audit
lightscan --web-scan http://target.local --web-checks dir sqli xss cors
```

---

## Key Features

* **AutoRecon Plugin Registry**: Decorator-based `@register_validator` system mapping ports to multiple check handlers without collisions.
* **Nuclei Matcher DSL**: Custom YAML PoC engine in `lightscan/templates/` with `and`/`or` condition logic, status codes, regex, and negative matchers.
* **UNIX Pipeline Ready**: Supports `-t -` (stdin targets) and `--output -` (stdout streaming). All console noise automatically redirects to `stderr`.
* **12+ Brute-Force Handlers**: SSH, SMB, RDP, FTP, MySQL, Postgres, MSSQL, Redis, Mongo, LDAP, VNC, Telnet with low-and-slow `--spray` mode.
* **Evasion & OPSEC**: Timing templates ($T0$–$T5$), packet fragmentation (`--fragment`), decoy IPs (`--decoy`), jitter, and ulimit auto-concurrency tuning.
* **IPv6 & Passive Recon**: SLAAC address prediction, dual-stack resolution (`--dual-stack`), and zero-packet traffic sniffing (`--passive`).

---

## Core CLI Flags

| Flag | Description |
| :--- | :--- |
| `--auto DOMAIN` | Full autonomous engagement chain |
| `--active -t TARGET` | 5-phase active red-team audit |
| `--mode {sweep,deep}` | Recon sweep (ports only) or deep audit |
| `-t, --target` | Target IP, range, CIDR, domain, or `-` (stdin) |
| `-p, --ports` | `22,80,443`, `1-1024`, or `top100` (default) |
| `--sv` | Service version detection & banner grabbing |
| `--cve` | Run CVE checkers and YAML PoC templates |
| `--brute PROTO` | Protocol brute-forcer (`ssh`, `smb`, `rdp`...) |
| `--web-scan URL` | OWASP web application scanner |
| `--stealth` | OPSEC mode: T1 timing, jitter, low concurrency |
| `-o, --output` | Output directory or `-` (stdout streaming) |
| `--format` | Output format: `json` (default), `html`, `nmap-xml`, `csv`, `minimal` |

---

## License

Authorized penetration testing and security research only. Released under the [MIT License](LICENSE).

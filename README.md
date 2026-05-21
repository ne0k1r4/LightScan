<div align="center">

```
██╗     ██╗ ██████╗ ██╗  ██╗████████╗███████╗ ██████╗  █████╗ ███╗   ██╗
██║     ██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔════╝ ██╔══██╗████╗  ██║
██║     ██║██║  ███╗███████║   ██║   ███████╗██║      ███████║██╔██╗ ██║
██║     ██║██║   ██║██╔══██║   ██║   ╚════██║██║      ██╔══██║██║╚██╗██║
███████╗██║╚██████╔╝██║  ██║   ██║   ███████║╚██████╗ ██║  ██║██║ ╚████║
╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
```

[![Version](https://img.shields.io/badge/version-2.0--PHANTOM-cc0000?style=for-the-badge&labelColor=0a0000)](https://github.com/ne0k1r4/LightScan)
[![Python](https://img.shields.io/badge/python-3.10+-cc0000?style=for-the-badge&logo=python&logoColor=white&labelColor=0a0000)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-cc0000?style=for-the-badge&labelColor=0a0000)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-cc0000?style=for-the-badge&labelColor=0a0000)](https://archlinux.org)
[![Author](https://img.shields.io/badge/author-ne0k1r4-cc0000?style=for-the-badge&labelColor=0a0000)](https://github.com/ne0k1r4)

**Async Network Recon & Attack Framework**  
Pure Python stdlib core · Zero hard dependencies · nmap-class scanning

</div>

---

## Features

| Module | Flag | Description |
|--------|------|-------------|
| **Port Scan** | `--scan` | Async TCP/UDP · banner grabbing · top-N port lists · CIDR ranges |
| **Service Version** | `--sv` | Banner-based service + version fingerprinting |
| **OS Detection** | `--os` | 70+ OS fingerprint signatures |
| **DNS Enum** | `--dns` | A/MX/NS/TXT/SOA · AXFR · crt.sh · subdomain brute |
| **CVE Templates** | `--cve` | 63 templates — RCE, unauth, misconfig, network exposure |
| **NSE Scripts** | `--script` | 12 built-in scripts — TLS, HTTP, SMB, SSH, FTP, DNS |
| **Web Scanner** | `--web-scan` | 43 checks — SQLi, XSS, SSTI, LFI, SSRF, CORS, smuggling |
| **Brute Force** | `--brute` | 12 protocols — SSH, FTP, HTTP, SMB, RDP, MySQL, LDAP... |
| **Credential Spray** | `--spray` | 1 password × N users, window-aware (AD lockout safe) |
| **Smart Mutation** | `--mutate` | Context-aware password generation from target info |
| **OAuth Audit** | `--oauth` | Open redirect · CSRF · PKCE downgrade · scope escalation |
| **Traceroute** | `--traceroute` | TCP SYN traceroute (raw socket / connect fallback) |
| **Scan Diff** | `--diff` | Compare two scan JSON reports |
| **Checkpoint** | `--resume` | Crash recovery — resume brute from last position |
| **IPv6** | `--ipv6` | Full IPv6 scanning support |
| **Adaptive Timing** | `--timing` | T0–T5 timing profiles (paranoid → insane) |
| **Evasion** | `--evasion` | Decoy IPs, fragmentation, random source ports |

---

## Install

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan
pip install -e .                     # core — zero hard deps
pip install -r requirements.txt      # optional: full brute capability
```

**Optional deps for full brute support:**
```bash
pip install paramiko                 # SSH brute
pip install pymysql                  # MySQL brute
pip install psycopg2-binary          # PostgreSQL brute
pip install ldap3                    # LDAP brute
pip install impacket                 # SMB/RDP brute (NTLMv2)
```

---

## Quick Start

```bash
# Port scan + service version + CVE check
lightscan --scan -t 10.0.0.1 -p top100 --sv --cve

# Full scan with scripts and report
lightscan --scan -t 10.0.0.1 -p top1000 --sv --cve \
  --script http_headers tls_cert_info ssl_weak_ciphers ssh_algorithms

# DNS enumeration
lightscan --dns target.com

# Web application scan
lightscan --web-scan http://target.com

# CIDR range scan
lightscan --scan -t 192.168.1.0/24 -p 22,80,443,3306,5432 --sv
```

---

## CVE Templates (63)

Templates use a YAML-based nuclei-style engine with multi-step matching.

<details>
<summary><b>CVEs & RCE</b> (12)</summary>

| ID | CVE | Severity | Description |
|----|-----|----------|-------------|
| log4shell | CVE-2021-44228 | CRITICAL | Log4j2 JNDI injection |
| spring4shell | CVE-2022-22965 | CRITICAL | Spring Framework RCE |
| proxyshell | CVE-2021-34473 | CRITICAL | Exchange Server RCE chain |
| proxylogon | CVE-2021-26855 | CRITICAL | Exchange Server SSRF+RCE |
| apache-path-traversal | CVE-2021-41773 | CRITICAL | Apache 2.4.49 path traversal |
| apache-struts-rce | CVE-2017-5638 | CRITICAL | Struts OGNL injection |
| drupalgeddon2 | CVE-2018-7600 | CRITICAL | Drupal pre-auth RCE |
| confluence-ognl-rce | CVE-2021-26084 | CRITICAL | Confluence OGNL injection |
| confluence-rce-2022 | CVE-2022-26134 | CRITICAL | Confluence unauthenticated RCE |
| vcenter-rce | CVE-2021-21985 | CRITICAL | VMware vCenter RCE |
| eternal-blue | CVE-2017-0144 | CRITICAL | SMB EternalBlue |
| bluekeep-detection | CVE-2019-0708 | CRITICAL | RDP pre-auth RCE |

</details>

<details>
<summary><b>Unauthenticated Access</b> (10)</summary>

Redis, MongoDB, Elasticsearch, Kibana, Grafana, Consul, Vault, Jupyter, Jenkins, GitLab

</details>

<details>
<summary><b>Misconfigurations</b> (12)</summary>

Docker API exposed, Kubernetes API, AWS metadata SSRF, Spring Actuator, Prometheus metrics, Grafana anon, phpinfo exposed, .env exposed, .git exposed, CORS wildcard, directory listing, backup files

</details>

<details>
<summary><b>Network Exposure</b> (10)</summary>

FTP anonymous, Telnet, SMBv1, SNMP public community, NFS exposed, RDP exposed, VNC exposed, rsync unauthenticated, ManageEngine RCE, HTTP/2 Rapid Reset

</details>

```bash
# List all templates
lightscan --list-templates

# Run specific template
lightscan --scan -t 10.0.0.1 -p 6379 --cve --cve-list redis-unauth

# Run all critical templates
lightscan --scan -t 10.0.0.1 -p top100 --cve --severity critical
```

---

## Scripts (12)

```bash
lightscan --list-scripts

# Run specific scripts
lightscan --scan -t target.com -p 443 \
  --script tls_cert_info ssl_weak_ciphers http_headers http_tech_detect
```

| Script | Ports | Description |
|--------|-------|-------------|
| `http_headers` | 80,443,8080 | Security header audit |
| `http_methods` | 80,443,8080 | Detect dangerous HTTP methods |
| `http_auth_detect` | 80,443,8080 | Detect Basic/NTLM/Kerberos auth |
| `http_cors_check` | 80,443,3000 | CORS misconfiguration detection |
| `http_tech_detect` | 80,443,8080 | Fingerprint 20 technologies |
| `tls_cert_info` | 443,8443,993 | Certificate expiry + SANs |
| `ssl_weak_ciphers` | 443,8443,993 | Detect RC4, DES, NULL, EXPORT ciphers |
| `ssh_algorithms` | 22 | Weak KEX/MAC/cipher detection |
| `smb_os_discovery` | 445 | OS + hostname via SMB negotiate |
| `smb_signing` | 445 | SMB signing disabled/not required |
| `dns_recursion` | 53 | Open DNS recursion check |
| `ftp_anon_write` | 21 | Anonymous FTP login + write test |

---

## Brute Force

```bash
# SSH
lightscan --brute ssh -t 10.0.0.1 -U root,admin -W passwords.txt

# HTTP form with CSRF token handling
lightscan --brute http -t 10.0.0.1 \
  --http-url http://10.0.0.1/login.php \
  --http-user-field username --http-pass-field password \
  --http-failure "Login failed" \
  -U admin -W passwords.txt --stop-first

# Password spray (AD lockout safe)
lightscan --brute smb -t 10.0.0.0/24 \
  -U file:users.txt -W "Summer2024!" \
  --spray --spray-window 1800

# Smart mutation from target context
lightscan --brute ssh -t 10.0.0.1 -U admin \
  --mutate --mutate-context "company=acme,year=2024"

# Resume interrupted brute
lightscan --brute ssh -t 10.0.0.1 -U admin -W rockyou.txt --resume

# Stealth with jitter
lightscan --brute ftp -t 10.0.0.1 -U admin -W passwords.txt --jitter 2 8
```

**Supported protocols:** SSH · FTP · SMTP · HTTP · MySQL · PostgreSQL · MSSQL · Telnet · VNC · SMB (NTLMv2) · RDP · LDAP

---

## Web Scanner

43 automated checks covering the OWASP Top 10 and beyond.

```bash
lightscan --web-scan http://target.com
lightscan --web-scan http://target.com --web-checks sqli xss ssti cors headers
```

| Category | Checks |
|----------|--------|
| Injection | SQLi GET/POST/blind/UNION · SSTI · Command injection · XXE |
| XSS | Reflected · Stored · DOM-based |
| Auth | Default credentials · JWT · OAuth misconfig |
| Access | LFI/path traversal · IDOR · File upload bypass |
| Infra | HTTP smuggling · Cache poisoning · Host header injection · CRLF |
| Discovery | Directory brute · Sensitive files · JS secret scan · API endpoints |
| Headers | CORS · Security headers · Clickjacking |

---

## Reports

Every scan auto-generates 3 formats:

```
lightscan_report.json   machine-readable, pipe into jq/other tools
lightscan_report.md     markdown with severity tables
lightscan_report.html   dark themed interactive dashboard
```

The HTML report includes:
- Severity breakdown donut chart
- Module findings bar chart
- Filterable findings table (click CRIT/HIGH/MED to filter)
- Full dark theme, no external dependencies

---

## Evasion & Timing

```bash
# Timing profiles (T0=slowest/stealthiest, T5=fastest/loudest)
lightscan --scan -t 10.0.0.1 -p top100 --timing T1

# Decoy scan (mix real source with fake IPs)
lightscan --scan -t 10.0.0.1 --decoys 10.0.0.5,10.0.0.6,ME

# Fragment packets (evade stateless firewalls)
lightscan --scan -t 10.0.0.1 --fragment

# Random source port
lightscan --scan -t 10.0.0.1 --source-port 53
```

---

## Architecture

```
lightscan/
├── cli.py              argument parser · async main · progress display
├── banner.py           ASCII banner · system info
├── core/
│   ├── engine.py       ScanResult · Severity · async task runner
│   ├── reporter.py     JSON · Markdown · HTML report generation
│   ├── target.py       CIDR expansion · host resolution
│   └── checkpoint.py   brute force resume state
├── scan/
│   ├── portscan.py     async TCP connect scanner
│   ├── rawscan.py      raw socket scanner (root)
│   ├── syn.py          SYN scan engine
│   ├── sversion.py     service version fingerprinting
│   ├── os_detect.py    OS fingerprinting (70+ sigs)
│   ├── dns.py          DNS enumeration
│   ├── scripts.py      NSE-style script engine (12 built-ins)
│   ├── passive.py      passive fingerprinting
│   ├── ipv6scan.py     IPv6 support
│   ├── adaptive.py     T0-T5 timing engine
│   └── evasion.py      decoys · fragmentation · source port
├── cve/
│   ├── template_engine.py  YAML template runner
│   └── checker.py          CVE check orchestration
├── brute/
│   ├── engine.py        async brute engine · spray · checkpoint
│   ├── mutation.py      smart password mutation
│   └── handlers/        12 protocol handlers
├── web/
│   └── scanner.py       43-check web application scanner
└── templates/           63 YAML detection templates
    ├── cve/
    ├── auth/
    ├── misconfig/
    └── network/
```

---

## Disclaimer

For authorized penetration testing, CTF use, and educational purposes only.  
Always obtain written permission before scanning systems you do not own.  
The developer is not responsible for misuse.

---

<div align="center">
<br>
<i>LightScan v2.0 PHANTOM · Developer: Light (Neok1ra)</i>
<br><br>

[![GitHub](https://img.shields.io/badge/github.com%2Fne0k1r4-cc0000?style=flat-square&labelColor=0a0000&logo=github&logoColor=white)](https://github.com/ne0k1r4)

</div>

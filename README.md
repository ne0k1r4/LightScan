# LightScan (v2.0-PHANTOM)

**Async Network Recon & Attack Framework**  
*Pure Python stdlib core · Zero hard dependencies · High-performance asynchronous scanning*

---

## Key Features

- **Port Scanning**: High-performance asynchronous TCP/UDP connect & SYN half-open scanning.
- **Service & OS Detection**: active/passive banner grabbing, 120+ OS fingerprint signatures, and RDP/SMB audits.
- **Vulnerability Checks**: Nuclei-style YAML template engine supporting 60+ CVEs (Log4Shell, ProxyShell, etc.).
- **Built-in Scripts**: NSE-style network scripts for TLS/SSL certificates, HTTP headers, SMB signing, and SSH algorithms.
- **Web App Scanner**: Core engine covering OWASP Top 10 checks (SQLi, XSS, SSRF, LFI, CORS, JWT alg:none, etc.).
- **Attack Suite**: Threaded protocol brute-forcer and credential sprayer supporting 12 network protocols with lockout safety and jitter controls.
- **Advanced Evasion**: Timing templates (T0-T5), decoy IPs, packet fragmentation, and source port randomization.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/ne0k1r4/LightScan
cd LightScan

# Install core framework (zero hard dependencies)
pip install -e .

# Install optional dependencies for full brute-force/NTLM capabilities
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Basic port scan with service version and CVE template checking
lightscan --scan -t 10.0.0.1 -p top100 --sv --cve

# Run web application vulnerability checks
lightscan --web-scan http://target.local

# Run weak SSH algorithm checking and cert audit
lightscan --scan -t 10.0.0.1 -p 22,443 --script ssh_algorithms tls_cert_info

# Automated protocol brute-force (with smart mutation)
lightscan --brute ssh -t 10.0.0.1 -U admin -W common --mutate
```

---

## Project Structure

```text
lightscan/
├── cli.py              # CLI Entry point & module orchestrator
├── banner.py           # CLI startup banner & environment checks
├── core/               # Engine core (reporter, checkpoint, task runners)
├── scan/               # Port scan engines, OS detection, DNS & traceroute
├── brute/              # Brute force protocol handlers & credential spraying
├── cve/                # CVE scanner & YAML template engine
├── web/                # Web application vulnerability scanner
└── templates/          # 60+ YAML detection templates (CVEs, auth exposure, etc.)
```

---

## Disclaimer

> [!WARNING]
> This tool is designed for authorized penetration testing, CTF games, and educational purposes only. Unauthorized scanning of network infrastructure is illegal. The author assumes no liability for misuse.

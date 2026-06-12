# LightScan v2.0 — PHANTOM

> Autonomous red-team recon and attack framework.  
> Point it at a domain. Walk away. Come back to a compromise map.

Pure Python core · Zero hard dependencies · Go companion binary for 10k+ concurrent scans

[![Languages](https://img.shields.io/badge/output-EN%20%7C%20ZH%20%7C%20RU%20%7C%20AR%20%7C%20ES-blue)](https://github.com/ne0k1r4/LightScan)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Go](https://img.shields.io/badge/go-1.21%2B-00ADD8)](https://go.dev)

---

## Quick Install

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan
pip install -e .                   # core
pip install -e ".[full]"           # optional: full requirements
make go                            # optional: build Go scanner binary
```
*Note: Python 3.10+. Root is required for raw socket modes (SYN scan, ICMP).*

---

## Quick Start

```bash
# Full autonomous recon -> scan -> exploit chain -> compromise map
lightscan --auto target.com

# Stealth active red-team scan on a subnet
lightscan --active -t 192.168.1.0/24 --stealth

# Classic version scan + vulnerability checking
lightscan --scan -t 10.0.0.1 -p top1000 --sv --cve

# Target credential auditing (smart passwords mutation)
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W common --mutate
```

---

## Core Capabilities

- **Autonomous Orchestration**: Multi-stage pipeline linking DNS enumeration, active port discovery, service versioning, CVE scanning, and exploit routing.
- **Go Companion Scanner**: Build via `make go` for 10,000+ concurrent connections sweeps (`./scanner/lscan`).
- **Diverse Modules**: DNS/Active Scanning, SSH/RDP/database Brute forcing, OWASP Web Vulnerability scanning, and YAML template checks.

---

## Legal

For authorized penetration testing, red team engagements, CTF, and security research only. You must have explicit written permission from target owners before scanning.

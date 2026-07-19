# LightScan (v2.1-PHANTOM)

An autonomous network recon and attack framework written in pure Python (no hard dependencies) with a Go companion binary for fast port scanning.

Point it at a domain, walk away, and come back to a compromise map.

## Setup

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan
pip install -e .                   # core engine (stdlib only)
pip install -e ".[full]"           # install optional deps (like Scapy for raw SYN scans)
make go                            # (optional) build the high-speed Go port scanner
```

*Note: Raw socket modes (SYN scans, ICMP pings, active OS detection) require root privileges.*

## Usage Examples

```bash
# Full auto mode: subdomains -> ports -> exploit checks -> pivot map
lightscan --auto target.com

# Stay in scope and scan quietly (evasion timing + random jitter)
lightscan --auto target.com --scope 10.0.0.0/8 --stealth

# Fast recon sweep (host discovery + port scan only, skips vulnerability checks & web audits)
lightscan --active -t 192.168.1.0/24 --mode sweep

# Pipe targets from stdin and output clean JSON results to stdout
cat targets.txt | lightscan --active --output - --format json | jq

# Target brute-forcing with smart wordlist mutations
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W common --mutate
```

## How --auto Works

LightScan chains 10 phases together sequentially:
1. Passive CT log searches (crt.sh) + active DNS bruteforcing.
2. IP resolution & scope checking.
3. Host discovery (ARP, ICMP ping, TCP fallbacks).
4. Port scanning (high-speed Scapy SYN or Go helper binary).
5. Service version detection & banner grabbing.
6. Vulnerability scanning via custom YAML templates (Nuclei-style).
7. Exploit chain construction (e.g., Redis unauth -> webshell).
8. Target brute-forcing (spraying cracked/default creds across hosts).
9. Active Active Directory / Domain Controller hunt.
10. Deep web application vulnerability scans (directory brute, SQLi, CORS).

All findings are stored in `lightscan_report.json` and parsed into an interactive HTML dashboard.

## Advanced Features

### Plugin Registry
Port-specific validators are dynamically registered using decorators rather than a hardcoded lookup map:
```python
@register_validator([389, 636])
async def _check_ldap_anon(host, port, timeout):
    # LDAP anonymous bind PoC
    ...
```

### Matcher DSL
Custom CVE checks in `lightscan/templates/` use a YAML DSL that supports complex matching logic, negations, and part filtering:
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

### UNIX Piping & Evasion
* Feed targets directly into `lightscan -t -` via stdin.
* Print reports to stdout using `--output -`.
* To prevent console noise from breaking JSON pipes, all banners, progress animations, and alerts automatically redirect to `stderr` when stdout redirection is active.

## Codebase Layout

* `lightscan/cli.py` - Main CLI parser & interactive TUI help guide.
* `lightscan/core/` - Core engine, report generators, target parsing, checkpoints.
* `lightscan/scan/` - Orchestrator, active/passive engines, port scanning, OS/service detection.
* `lightscan/brute/` - Multithreaded brute force engine and protocol handlers.
* `lightscan/cve/` - Vulnerability verification & YAML template engine.
* `lightscan/web/` - Web app vulnerability scanner.
* `lightscan/templates/` - Detection templates for common exposures and CVEs.
* `scanner/` - High-performance Go port scanner source.

## License & Legal
Penetration testing is only legal on targets you have explicit, written permission to audit. Use responsibly. Released under the MIT License.

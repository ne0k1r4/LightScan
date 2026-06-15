# Changelog


## v2.1.0 — 2026-06-13
- feat: host discovery (ICMP ping + ARP sweep) before port scan
- feat: passive sniffer mode (ARP/DNS/mDNS/DHCP/NetBIOS) — zero packets
- feat: nmap-xml, HTML, CSV, minimal output formats
- feat: nmap-style protocol probes (SSH/HTTP/FTP/SMTP/MySQL/Redis/Postgres/MongoDB/RDP/Memcached)
- feat: SMB null session + share listing + RPC endpoint mapping
- feat: crt.sh CT log passive subdomain discovery
- feat: DKIM selector probing (18 selectors)
- feat: SNMP v1/v2c enumeration (pure stdlib — sysDescr, interfaces, processes)
- feat: IPv6 rewrite — ICMPv6 ND, dual-stack detection, SLAAC EUI-64 prediction
- feat: drop-rate detector in adaptive engine — halts on IDS throttle
- feat: SMB null session + anon login pre-check before credential brute
- fix: sversion not wired into --sv flag
- fix: IPv6 link-local zone ID stripping
- fix: SNMP BER multi-byte length parser
- fix: SMB null session error handling

All notable changes to LightScan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.0.0] — 2026-06-12

This release turns LightScan from a collection of scan modules into a
fully autonomous red-team engagement engine. The biggest change is that
you no longer need to chain commands manually — `--auto` does it for you.

### Added

**Autonomous pipeline (`--auto`)**
- 10-stage engagement engine: DNS enumeration → asset resolution → host
  discovery → port scan → service profiling → CVE validation → exploit
  chain analysis → credential attack → DC/AD detection → web deep-scan
- `TargetContext` shared state: OS hints, found credentials, and open ports
  persist across all stages so later stages skip irrelevant checks
- `compromise_map_<domain>.json` output — structured attack graph with
  ordered exploit chains per host

**Active scan engine (`--active`)**
- Phase 1: Host discovery via ICMP raw socket, ARP table (`/proc/net/arp`
  for LAN hosts), and TCP-connect fallback — works without root
- Phase 2: Async port scan with intensity profiles (9 ports to all ports)
- Phase 3: Protocol-specific deep probing — sends the right handshake
  per service and extracts version from the response
- Phase 4: Vulnerability validation with real PoC payloads (FTP anonymous,
  Redis `CONFIG SET` webshell, MongoDB unauthenticated, SMBv1/EternalBlue,
  LDAP anonymous bind, Telnet, HTTP exposure paths)
- Phase 5: Pivot and exploit chain suggestions from confirmed vulns

**Exploit chain engine**
- Decorator-based chain registry — each chain builder is one function
- Context-aware: skips Windows-only chains on Linux hosts, feeds cracked
  credentials into DCSync chain automatically
- Covers: Redis RCE, EternalBlue, Tomcat WAR deploy, `.env` harvest,
  Git repo dump, Spring Actuator heap/SSRF, LDAP AD recon, FTP anon,
  MongoDB dump, DCSync (fires only when DC + valid creds both present)

**Internationalization (`--lang`)**
- i18n layer with translations for all CLI output strings
- Languages: English (en), Chinese Simplified (zh), Russian (ru),
  Arabic (ar), Spanish (es)
- Auto-detected from `$LIGHTSCAN_LANG` or `$LANG` environment variable
- Override per-run with `lightscan --lang zh --auto target.com`

**Go scanner companion binary (`scanner/lscan`)**
- High-performance TCP connect scanner written in Go
- Handles 10,000+ concurrent connections efficiently for large subnet sweeps
- CIDR, range, hostname, and file target parsing
- NDJSON output for easy Python interop
- Built with `make go` — zero runtime dependencies

**CLI additions**
- `--auto DOMAIN` — full autonomous engagement from a single domain
- `--active` — 4-phase active scan on any target
- `--intensity 1-5` — controls port breadth (9 ports to all ports)
- `--scope CIDR/DOMAIN` — hard scope enforcement, blocks out-of-scope probes
- `--stealth` — T1 timing + 1-3s jitter + reduced concurrency
- `--skip-web`, `--skip-brute` — skip specific stages of `--auto`
- `--lang en|zh|ru|ar|es` — output language selection

**Packaging**
- `pyproject.toml` replacing `setup.py` (PEP 517/518 compliant)
- `extras_require[full]` — `pip install -e ".[full]"` installs everything
- `Makefile` with `install`, `full`, `go`, `test`, `lint`, `clean`, `smoke` targets
- Pinned dependency versions in `requirements.txt`

### Changed

- Scope enforcement now happens at the CLI layer, not inside scan modules,
  so modules remain reusable without side effects
- Module docstrings rewritten in plain language throughout the codebase
- README condensed to essentials — install, quick start, flag table, layout

### Fixed

- `scapy`, `aiohttp`, `PyYAML` were used but missing from `requirements.txt`
- `setup.py` lacked `url`, `license`, and classifier metadata

---

## [1.5.0] — 2026-05-30

### Added
- AF_PACKET stealth scan with source port spoofing (`--stealth-scan --spoof-sport`)
- IPv6 / dual-stack scanning (`-6`, `--dual-stack`)
- OS fingerprint database v2 — 120+ signatures (`--os-v2`)
- Evasion layer: decoy IPs, packet fragmentation, source port randomization
- RDP raw protocol probe with NLA/SSL/cert detection (`--rdp-probe`)
- SMB NTLM raw handler for brute force without impacket dependency
- OAuth 2.0 security audit (`--oauth`)
- Scan diff comparison (`--diff old.json new.json`)
- Adaptive timing that adjusts rate based on RTT/loss

### Changed
- HTML report upgraded to dark-themed dashboard with donut chart and severity filter
- Markdown report groups duplicate findings by parameter to reduce noise

---

## [1.0.0] — 2026-04-10

Initial release.

- Async TCP/UDP port scanner with SYN half-open mode
- Service version detection (nmap -sV equivalent, 500+ signatures)
- Passive fingerprinting: TLS/JA3S, HTTP headers, SSH banner entropy
- OS detection: passive SYN-ACK analysis + active T2-T7 multi-probe
- DNS enumeration: AXFR, crt.sh, subdomain brute
- CVE checker: EternalBlue, Log4Shell, Spring4Shell, Heartbleed, ShellShock
- YAML template engine with 60+ detection templates
- NSE-style script engine (TLS, HTTP, SMB, SSH, DNS scripts)
- Brute force engine: 12 protocols, lockout detection, credential spray
- Web scanner: OWASP Top 10 (SQLi, XSS, SSRF, LFI, CORS, JWT, secrets)
- JSON + Markdown + HTML report generation
- Checkpoint/resume for interrupted scans
- TCP traceroute

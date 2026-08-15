# Changelog

## Unreleased

### v2.6.0 — Evidence Interoperability and Passive OS Context

#### Added
- `lightscan/core/nmap_xml.py`: a read-only, bounded Nmap XML importer that rejects DTD/entity declarations, normalizes imported OS matches and open-service observations into LightScan results, and never executes Nmap or sends packets.
- `lightscan/scan/os_evidence.py`: independently authored, conservative OS-family inference from distinctive service metadata already collected by LightScan or imported from XML; it has no network I/O and does not reproduce third-party fingerprint databases.
- `tests/test_nmap_xml_import.py`: local-only coverage for IPv4/IPv6 XML import, OS/CPE/service evidence preservation, malformed-input rejection, and DTD/entity rejection.
- `tests/test_os_evidence.py`: local-only coverage for distinctive evidence inference, generic-product abstention, and per-port signal de-duplication.

#### Changed
- `lightscan/cli.py`: adds offline `--import-nmap-xml PATH` and no-extra-probe `--os-evidence` controls, including concise help and report integration.
- `RESEARCH_SOURCES.md`: records official Nmap OS-detection and licensing references and establishes that LightScan does not vendor or copy the Nmap OS database.
- `README.md`: documents offline Nmap XML interoperability, passive OS evidence, operator examples, and the Nmap Public Source License boundary.
- `pyproject.toml`, `setup.py`, `lightscan/__init__.py`, `lightscan/banner.py`, and `lightscan/core/reporter.py`: align package, runtime, and XML/HTML report identity at `2.6.0`.
- `CHANGELOG.md`: records the complete v2.6.0 release change set for atomic Git delivery.

#### Fixed
- Imported XML is now constrained before parsing so entity declarations and oversized artifacts cannot become an XML-processing hazard.
- OS inventory context now has an explicit no-extra-packet path rather than requiring active fingerprint probes for every enrichment workflow.

### v2.5.0 — Advanced Reliability Controls

#### Added
- `lightscan/core/runtime_telemetry.py`: portable process-resource snapshots reporting open file descriptors where available, soft/hard descriptor limits, and maximum resident memory.
- `lightscan/scan/aimd.py`: a small additive-increase/multiplicative-decrease controller for loss-aware adaptive concurrency.
- `tests/test_reliability_telemetry.py`: local-only tests for jittered retry delays, transient error classification, retry metrics, and process telemetry.
- `tests/test_aimd_ipv6.py`: local-only tests for the AIMD control law, bracketed IPv6 normalization, and IPv6 loopback TCP discovery.

#### Changed
- `lightscan/scan/streaming.py`: classifies resource-pressure and temporary network failures as transient, retries filtered and transient outcomes with bounded randomized delay, exports retry/telemetry metrics, and lets the adaptive window use AIMD feedback.
- `scanner/main.go` and `scanner/main_test.go`: add bracketed IPv6 literal/CIDR readiness, transient retry classification, bounded jittered delays, retry aggregate fields, and process runtime telemetry to the Go NDJSON completion summary.
- `lightscan/scan/go_runner.py`: forwards retry-jitter settings to `lscan` and retains the Go runtime telemetry summary in the common performance metadata.
- `lightscan/core/target.py`: normalizes bracketed IPv6 literals such as `[::1]` before resolution and scan planning.
- `lightscan/cli.py`: adds validated `--retry-jitter` control, forwards it to both execution engines, exposes the setting in scan status and concise help, and aligns CLI identity at v2.5.
- `pyproject.toml`, `setup.py`, `lightscan/__init__.py`, `lightscan/banner.py`, and `lightscan/core/reporter.py`: align packaging, runtime banners, and XML/HTML report metadata at `2.5.0`.
- `README.md`, `PERFORMANCE.md`, and `CHANGELOG.md`: document the v2.5 reliability controls, adaptive behaviour, IPv6 normalization, local validation scope, and release record.

#### Fixed
- Retry behavior now distinguishes filtered results from temporary local resource pressure instead of treating all non-open outcomes as equivalent.
- Adaptive scan concurrency now reduces promptly after loss feedback and recovers conservatively after sustained success.

### v2.4.0 — Constrained Lua Checks and Loopback Benchmark

#### Added
- `lightscan/scan/lua_checks.py`: an NSE-inspired Lua 5.4 service-check engine that discovers declarative metadata, runs checks in a short-lived restricted process, permits only safe categories, and normalizes findings into `ScanResult`.
- `lightscan/lua_scripts/tcp_banner_inventory.lua` and `lightscan/lua_scripts/http_security_headers.lua`: bundled non-destructive inventory and HTTP response-header checks.
- `LUA_CHECKS.md`: Lua API, safe execution boundary, observation contract, review checklist, and custom-check workflow.
- `tools/benchmark_loopback.py`: a loopback-only three-engine 1–65,535 TCP-connect benchmark harness that refuses arbitrary targets.
- `benchmark_results/loopback_65535.json` and `benchmark_results/loopback_65535_chart.png`: recorded three-trial local benchmark data and visualization.
- `BENCHMARK_65535.md`: benchmark methodology, raw results, analysis, scope limits, and reproduction instructions.
- `tests/test_lua_checks.py`: local-only coverage for safe discovery, forbidden-capability rejection, HTTP check findings, and enforced execution timeouts.

#### Changed
- `lightscan/cli.py`: adds `--lua-script`, `--lua-script-tags`, `--lua-script-dir`, `--list-lua-scripts`, and `--lua-concurrency`; Lua checks are scheduled only after confirmed port discovery and cannot be combined with retention-free streaming.
- `pyproject.toml`: packages bundled `.lua` checks so installed wheels retain the extension library.
- `README.md`, `PERFORMANCE.md`, and `RESEARCH_SOURCES.md`: document the v2.4 Lua contract, local benchmark results, and official NSE/TCP-connect design references.
- `pyproject.toml`, `setup.py`, `lightscan/__init__.py`, `lightscan/banner.py`, `lightscan/cli.py`, and `lightscan/core/reporter.py`: release identity and report metadata are aligned at `2.4.0`.

#### Fixed
- `lightscan/scan/lua_checks.py`: safely moves observed service context through a temporary JSON file rather than interpolating untrusted banner content into generated Lua source.
- `lightscan/scan/lua_checks.py`: corrected Lua JSON-wrapper escaping and table-key handling under Lua 5.4, and converts subprocess timeouts into controlled check-specific errors.

### v2.3.0 — Incremental Results and Telemetry

#### Added
- `lightscan/core/ndjson.py`: durable NDJSON event writer that immediately emits each open result and closes with one metadata and performance summary event.
- `lightscan/core/metrics.py`: portable `lightscan-performance/v1` snapshots, derived throughput/outcome rates, and offline baseline-versus-candidate comparisons.
- `tests/test_ndjson_metrics.py`: local-only coverage for event stream ordering, retention-free scans, snapshot generation, and metric comparison.
- `RESEARCH_SOURCES.md`: authoritative performance, service-detection, and structured-output design references retained for future maintainers.

#### Changed
- `lightscan/scan/streaming.py`: accepts result callbacks and `retain_results=False`, allowing high-scale scans to avoid retaining the open-result list while still counting metrics.
- `lightscan/scan/go_runner.py` and `scanner/main.go`: Go NDJSON now ends with a compact completion summary; the Python bridge retains aggregate attempts, outcome, retry, and elapsed metrics while streaming only open results.
- `lightscan/cli.py`: adds `--stream-open`, `--metrics-out`, and offline `--compare-metrics` controls, concise help coverage, and an explicit guard because retention-free streaming cannot supply the open-port list required by `--sv`.
- `tests/test_streaming_scanner.py` and `scanner/main_test.go`: verify Go summary metrics and native aggregate counters.
- `README.md` and `PERFORMANCE.md`: document retention-free NDJSON streams, portable snapshots, controlled comparisons, and v2.3 benchmark guidance.
- `pyproject.toml`, `setup.py`, `lightscan/__init__.py`, `lightscan/banner.py`, `lightscan/cli.py`, and `lightscan/core/reporter.py`: release identity and generated report metadata are aligned at `2.3.0`.

#### Fixed
- `scanner/main.go`: aggregate outcome metrics remain available even with `--open`, preventing high-scale Go runs from losing closed, filtered, retry, or skipped counts.

### v2.2.0 — Streaming Performance Architecture

#### Added
- `lightscan/scan/streaming.py`: bounded asynchronous TCP scheduler with a fixed-capacity work queue, fair port-major host grouping, global connection-rate limiting, adaptive RTT/loss feedback window, per-host concurrency, retry-aware timeout classification, host-time ceilings, and runtime metrics.
- `lightscan/scan/go_runner.py`: streamed NDJSON bridge from the optional Go `lscan` binary into LightScan's common `ScanResult` and reporting contract.
- `scanner/main.go`: rewritten Go TCP engine with bounded job/result channels, exact target/port input validation, retry and rate controls, per-host limits, host timeouts, and writer completion synchronization.
- `scanner/main_test.go` and `tests/test_streaming_scanner.py`: native Go and local-only Python coverage for bounded planning, queue limits, rate gates, streaming results, and Go bridge compatibility.
- `PERFORMANCE.md`: operator controls, architectural boundaries, benchmark methodology, and references for the v2.2 execution model.

#### Changed
- `lightscan/cli.py`: `--scan` now uses the streaming scheduler and exposes `--go-engine`, `--go-binary`, `--max-rate`, `--retries`, `--host-timeout`, `--per-host-concurrency`, `--host-group-size`, `--no-banner-grab`, and `--no-adaptive`.
- `Makefile`: `make test` now runs both Python and Go tests when Go is available.
- `.gitignore`: excludes the platform-specific `scanner/lscan` build output so source commits remain portable.
- `README.md`: documents the v2.2 scheduler, Go execution engine, performance controls, and local validation workflow.
- `pyproject.toml`, `setup.py`, `lightscan/__init__.py`, `lightscan/banner.py`, `lightscan/cli.py`, and `lightscan/core/reporter.py`: release identity and report metadata are aligned at `2.2.0`.

#### Fixed
- `scanner/main.go`: Go output now waits for the NDJSON writer to drain, preventing process exit from truncating scan output.
- `scanner/main.go`: target expansion and job buffers are explicitly bounded rather than scaling unchecked with input size or configured worker count.

### v2.1.1 — Reliability and Reporting Foundation

### Added
- `lightscan/core/target.py`: bounded target planning with a default 65,536-target ceiling, strict CIDR/range/file parsing, stable de-duplication, and explicit `TargetSpecError` messages before network activity begins.
- `lightscan/cli.py`: `--max-targets` and `--version-concurrency` controls, plus a scan-first service-probe flow when `--scan --sv` are combined.
- `lightscan/scan/sversion.py`: normalized `ScanResult` service-probe adapter with protocol-derived `method=probed` and `confidence=10` evidence.
- `tests/test_target_validation.py`, `tests/test_service_version.py`, and `tests/test_reporter_formats.py`: local-only regression coverage for scan planning, probes, and report contracts.

### Changed
- `lightscan/core/reporter.py`: JSON now retains complete result data while keeping legacy `host` and `service` aliases; Nmap-style XML now contains run statistics, port state, service method/confidence, and script records for non-port findings; HTML escapes untrusted banner text.
- `lightscan/README.md`: rewritten around authorized inventory workflows, target limits, scan-first version detection, and output contracts.
- `pyproject.toml` and `setup.py`: package metadata was updated for the authorized inventory and assessment positioning, and the required `PyYAML` dependency was declared for the bundled template engine.

### Fixed
- `lightscan/cli.py` and `lightscan/scan/sversion.py`: repaired the broken `--sv` path, which imported an undefined `detect_services` symbol.
- `lightscan/scan/sversion.py`: service-probe connections now close deterministically and consistently honor their supplied timeout.
- fix: template audit — dropped fabricated CVE IDs from ~30 unauth/misconfig checks; they now carry honest descriptive IDs with real remediation and references.
- refactor: merged duplicate kibana / docker-api / prometheus / kubernetes-api / bluekeep / grafana checks (58 templates).
- fix: BlueKeep probe now exchanges the mstshash cookie for accurate pre-NLA detection.

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

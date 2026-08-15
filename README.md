# LightScan v2.6.0

**LightScan** is an asynchronous, authorized-network inventory and assessment scanner. It combines bounded target planning, streaming TCP-connect discovery, protocol-aware service observations, structured reporting, optional Go acceleration, and a constrained Lua extension layer. Version 2.6.0 adds a read-only bridge for user-provided Nmap XML evidence and conservative OS-family inference from service information already collected.

> **Authorization and safety boundary.** Scan only systems that you own or are explicitly authorized to test. Start with a small approved target scope, conservative concurrency, and a narrow port set. LightScan is designed for inventory and defensive assessment; its built-in limits reduce accidental scale, but they do not replace written authorization, change-management approval, or operational monitoring.

## Contents

| Section | Purpose |
| --- | --- |
| [Quick start](#quick-start) | Install and run a bounded authorized inventory pass. |
| [Installation](#installation) | Core, development, Go, and optional Lua setup. |
| [Core workflow](#core-workflow) | Discovery, service enrichment, reporting, and evidence import. |
| [Capabilities](#capabilities) | What LightScan v2.6.0 does and its operating boundaries. |
| [Controls](#key-controls) | Safety, performance, evidence, and output options. |
| [Nmap interoperability](#nmap-interoperability) | Offline Nmap XML import without copying Nmap databases. |
| [Benchmarking](#local-loopback-benchmarking) | Reproducible local-only comparison with Nmap. |
| [Development](#development-and-validation) | Test, build, and contribution workflow. |

## Quick start

Clone the repository, install the core package, and confirm that the short help screen renders.

```bash
git clone https://github.com/ne0k1r4/LightScan.git
cd LightScan
python -m pip install -e .
lightscan --no-banner --help
```

Run an initial TCP inventory pass only against a **reviewed and authorized** scope. This example uses the documentation address block `192.0.2.0/28`, a conservative target cap, explicit connection-rate limit, bounded per-host concurrency, and structured JSON output.

```bash
lightscan --scan -t 192.0.2.0/28 -p top100 \
  --max-targets 16 --concurrency 128 --per-host-concurrency 16 \
  --max-rate 250 --retries 1 --retry-jitter 0.15 \
  --host-timeout 10 --format json --output reports
```

After TCP discovery, use `--sv` only when service metadata is needed. With `--scan --sv`, LightScan limits service observations to confirmed open ports, reducing unnecessary application-layer traffic.

```bash
lightscan --scan -t file:approved-targets.txt -p 22,80,443,3306 \
  --max-targets 256 --sv --version-concurrency 10 \
  --format json --output reports
```

## Installation

### Requirements

| Component | Required | Purpose |
| --- | ---: | --- |
| Python 3.10 or later | Yes | Core CLI, scheduler, reports, import bridge, and tests. |
| `PyYAML==6.0.1` | Yes | Bundled YAML template support. Installed automatically by the core package. |
| Go toolchain | Optional | Builds the high-concurrency `scanner/lscan` TCP-connect companion. |
| Lua 5.4 runtime | Optional | Executes the constrained, reviewed Lua check layer. |
| Nmap | Optional | Required only to create Nmap XML artifacts or run the local comparison harness; importing existing XML does not require Nmap. |

### Core installation

The minimal core installation provides bounded TCP discovery, reports, performance snapshots, offline Nmap XML import, and passive OS evidence.

```bash
python -m pip install -e .
```

For an isolated environment, create a virtual environment first.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

### Development installation

Install test and lint dependencies when working on the repository.

```bash
python -m pip install -e ".[dev]"
make test
```

### Optional protocol modules

The `full` extra installs optional libraries used by selected protocol and raw-packet modules. Install it only when those approved workflows are needed.

```bash
python -m pip install -e ".[full]"
```

The optional dependency set currently includes Paramiko, database protocol clients, LDAP support, Scapy, and HTTP support. The bounded TCP-connect inventory core does **not** require these packages.

### Build the Go companion

The Go engine implements the same bounded TCP-connect contract and produces NDJSON that the Python bridge normalizes into the common report model.

```bash
make go
./scanner/lscan --help
```

Use it from the main CLI after building.

```bash
lightscan --scan --go-engine --go-binary scanner/lscan \
  -t file:approved-targets.txt -p 22,80,443 \
  --max-targets 256 --concurrency 512 --per-host-concurrency 32 \
  --max-rate 500 --retries 1 --host-timeout 10 --output reports
```

### Optional constrained Lua checks

On Debian or Ubuntu, install a Lua 5.4 runtime with the platform package manager.

```bash
sudo apt-get install lua5.4
lightscan --list-lua-scripts
```

Lua checks are intentionally constrained. They receive a read-only service observation context after discovery; filesystem, process execution, dynamic module loading, and direct network APIs are unavailable. Review any additional local scripts before supplying `--lua-script-dir`.

## Core workflow

### 1. Plan an approved target scope

Use direct IPs, CIDRs, approved text files, or standard input. LightScan expands and de-duplicates target input before scanning and refuses a scope larger than the configured `--max-targets` ceiling. The default ceiling is `65536`, but a lower project-specific limit is recommended.

```bash
# A reviewed file may contain blank lines and comments.
lightscan --scan -t file:approved-targets.txt --max-targets 128 -p 22,80,443

# Read an approved list from standard input.
cat approved-targets.txt | lightscan --scan -t - --max-targets 128 -p top100
```

### 2. Discover TCP services with bounded controls

The streaming scanner does not create one coroutine for every host-port pair. It produces work incrementally, applies global and per-host limits, and optionally caps connection starts per second.

```bash
lightscan --scan -t 192.0.2.0/28 -p 22,80,443,8080 \
  --concurrency 128 --per-host-concurrency 16 --host-group-size 64 \
  --max-rate 250 --host-timeout 10 --no-banner-grab \
  --format json --output reports
```

Retry behavior distinguishes clear refusal from filtered, timeout, and temporary resource-pressure outcomes. `--retry-jitter` randomizes the bounded retry delay to avoid synchronized reattempts; use `0` only when deterministic local benchmarking is more important than production-like pacing.

### 3. Enrich confirmed open ports

Service observations run only against discovered open ports when `--scan --sv` is combined. This separates inventory discovery from application-level enrichment.

```bash
lightscan --scan -t 192.0.2.10 -p 22,80,443,3306 \
  --sv --version-concurrency 10 --timeout 3 \
  --format json --output reports
```

### 4. Add passive OS context without new probes

`--os-evidence` reads only service information already collected by `--sv` or imported from Nmap XML. It emits a conservative family-level observation only when distinctive vendor or product signals exist. Generic products such as `nginx` or `Apache` alone are intentionally insufficient.

```bash
lightscan --scan -t 192.0.2.10 -p 22,80,443 --sv --os-evidence \
  --format json --output reports
```

### 5. Select optional reviewed Lua checks

Run only reviewed, non-destructive checks after discovery has identified open ports.

```bash
lightscan --scan -t 192.0.2.10 -p 80,443,8080 \
  --lua-script http-security-headers --lua-concurrency 5 \
  --format json --output reports
```

`--stream-open` is a retention-free discovery mode and cannot be combined with `--sv` or Lua checks, because those stages require the confirmed-open-port list. Run enrichment as a subsequent reviewed pass.

### 6. Produce reports and performance evidence

```bash
# Write a normal JSON report.
lightscan --scan -t file:approved-targets.txt -p top100 --output reports --format json

# Stream each confirmed open result as NDJSON and keep aggregate metrics.
lightscan --scan -t file:approved-targets.txt -p top100 \
  --stream-open reports/open.ndjson --metrics-out reports/run-a.json --no-report

# Compare two previously written snapshots. This command performs no network activity.
lightscan --compare-metrics reports/run-a.json reports/run-b.json
```

## Capabilities

| Capability | v2.6.0 behavior | Boundary |
| --- | --- | --- |
| **Bounded target planning** | Parses IPs, CIDRs, last-octet ranges, standard input, and `file:` targets; de-duplicates input and enforces a ceiling. | Authorization and scope review remain the operator’s responsibility. |
| **Streaming TCP discovery** | Bounded producer/consumer scheduler with global concurrency, per-host concurrency, fair host groups, rate caps, timeouts, and optional banner collection. | TCP connect discovery; not a replacement for every raw-packet scan technique. |
| **Reliability controls** | Outcome-aware retry classification, jittered retry backoff, runtime file-descriptor/memory telemetry, and AIMD feedback. | Tune only after baseline measurements on approved systems. |
| **IPv6 readiness** | Normalizes bracketed IPv6 literals and supports IPv6 input paths in the Go engine. | Network policy and routing must still be validated by the operator. |
| **Go execution engine** | Optional high-connection-count TCP-connect engine with NDJSON summary telemetry. | Requires a separately built `lscan` binary. |
| **Service evidence** | Protocol-aware observations and normalized service/version records for common services. | Service identification is evidence-based and probabilistic. |
| **Constrained Lua checks** | Reviewed Lua 5.4 checks operate on read-only observations after open-port discovery. | Not a general NSE interpreter; unreviewed scripts should not be trusted. |
| **Nmap XML interoperability** | Imports OS matches, CPEs, and open-service observations from a local Nmap XML artifact. | Offline only; does not execute Nmap or vendor Nmap databases. |
| **Passive OS evidence** | Uses distinctive existing service metadata to infer a conservative OS family. | It abstains when evidence is generic or insufficient. |
| **Structured reporting** | JSON, CSV, HTML, minimal text, and Nmap-style XML output. | HTML escapes untrusted banner text before rendering. |

## Key controls

| Option | Default | Operational effect |
| --- | ---: | --- |
| `-t, --target` | — | IP, CIDR, last-octet range, hostname, `file:targets.txt`, or `-` for standard input. |
| `--max-targets N` | `65536` | Reject target expansion larger than `N` before scanning. |
| `-p, --ports` | `top100` | Comma-separated ports, ranges such as `1-1024`, or `top100`. Invalid values are rejected before activity begins. |
| `--scan` | Off | Run bounded streaming TCP-connect discovery. |
| `--concurrency N` | Auto-tuned | Cap total concurrent TCP jobs; default tuning considers file-descriptor limits. |
| `--per-host-concurrency N` | `32` | Cap in-flight TCP connections for a single target. |
| `--host-group-size N` | `256` | Set the host chunk used by the fair work producer. |
| `--max-rate N` | `0` | Cap connection starts per second; `0` disables the explicit cap. |
| `--retries N` | `1` | Limit retries for timeout, filtered, and transient local-resource outcomes. |
| `--retry-jitter FRACTION` | `0.15` | Randomize retry backoff by a fraction from `0.0` through `1.0`. |
| `--host-timeout SECONDS` | `0` | Bound wall-clock time spent on one target; `0` disables the limit. |
| `--adaptive` / `--no-adaptive` | On / Off | Use feedback-based concurrency adjustment, or lock controls for repeatable benchmarks. |
| `--stream-open PATH` | Off | Emit each confirmed open result as NDJSON; use `-` for standard output. |
| `--metrics-out PATH` | Off | Write a portable `lightscan-performance/v1` snapshot. |
| `--compare-metrics A B` | Off | Compare two local metric snapshots without scanning. |
| `--go-engine` | Off | Select the compiled Go TCP-connect engine. |
| `--go-binary PATH` | Auto-discovery | Use a specific `lscan` executable. |
| `--sv` | Off | Observe service product/version metadata on confirmed open ports. |
| `--version-concurrency N` | `20` | Cap concurrent service observations. |
| `--os-evidence` | Off | Infer a conservative OS family from existing service evidence only. |
| `--import-nmap-xml PATH` | Off | Offline import of OS and open-service observations from local Nmap XML. |
| `--lua-script CHECK` | Off | Run selected constrained Lua checks on confirmed open ports. |
| `--lua-script-tags CATEGORY` | Off | Run constrained Lua checks in selected safe categories. |
| `--lua-script-dir DIR` | Off | Add a specifically reviewed directory of Lua checks. |
| `--format FORMAT` | `json` | Select `json`, `nmap-xml`, `html`, `csv`, or `minimal`. |
| `-o, --output PATH` | `.` | Select output directory, or `-` for standard output. |

## Nmap interoperability

Nmap offers broad scan techniques, an extensive OS fingerprint database, version probes, and the NSE script ecosystem.[1] [2] [3] LightScan is not presented as a replacement for that mature breadth. Instead, v2.6.0 adds an interoperability path that preserves Nmap evidence inside LightScan’s common report schema.

### Import a local Nmap XML artifact

```bash
lightscan --import-nmap-xml approved-nmap.xml --format json --output reports

# Add a LightScan family-level interpretation based only on the imported services.
lightscan --import-nmap-xml approved-nmap.xml --os-evidence --format html --output reports
```

The importer accepts a regular local file, rejects XML DTD/entity declarations, enforces a 64 MiB input limit, and imports only `open` or `open|filtered` service observations to keep inventory reports focused. It preserves available OS match names, reported accuracy, OS classes, CPEs, port state, service product/version fields, and source context.

Nmap and its fingerprint data are distributed under the Nmap Public Source License, which contains additional conditions beyond GPLv2.[4] LightScan therefore does not vendor or copy the Nmap OS database. Use a local Nmap installation to create artifacts under its own license terms, then import those artifacts through this offline bridge.

## Output contracts

| Format | Primary use | Notes |
| --- | --- | --- |
| `json` | Complete machine-readable inventory evidence | Preserves common result fields and each result’s full `data` object. |
| `nmap-xml` | Tool interoperability | Includes run metadata, host/port state, service information, and non-port findings as script records. |
| `html` | Human review | Escapes untrusted text before rendering. |
| `csv` | Spreadsheet analysis | Flat result export. |
| `minimal` | Terminal or compact processing | Reduced textual output. |
| `NDJSON` via `--stream-open` | Incremental automation | Emits confirmed open results immediately, followed by a summary event. |

## Local loopback benchmarking

The repository includes a guarded comparison harness for a controlled **local-only** TCP-connect workload. It refuses arbitrary targets and uses `127.0.0.1` with ports `1-65535`; it does not measure Internet, WAN, appliance, UDP, raw-packet, OS-detection, version-detection, or scripting performance.

```bash
make go
python tools/benchmark_loopback.py --trials 3 --concurrency 1024 --timeout 1.0 \
  --output benchmark_results/loopback_65535_v26.json
```

The harness executes equivalent TCP-connect scans for the LightScan Python engine, the LightScan Go engine, and Nmap `-sT`, with retries disabled and banners disabled. See [BENCHMARK_V26.md](BENCHMARK_V26.md) for the measured v2.6.0 environment, raw trial data, interpretation, and feature comparison.

> A lower elapsed time from one narrow loopback workload is not a general claim of superiority. Compare only equivalent target scope, port range, scan type, concurrency, retries, timeout, banner behavior, and system load. Nmap’s documentation likewise notes that timing and parallelism choices affect both speed and accuracy.[5]

## Development and validation

Run the complete local suite, including Python and Go tests.

```bash
python -m pip install -e ".[dev]"
make test
```

Build distributable artifacts after validation.

```bash
uv build --wheel
make go
```

The v2.6.0 release includes local-only coverage for bounded target parsing, port validation, streaming scheduler limits, jittered retries, transient classification, runtime telemetry, AIMD feedback, IPv6 normalization, Go bridge behavior, NDJSON streams, metric snapshots, reporter formats, constrained Lua checks, offline Nmap XML import, and passive OS-evidence fusion.

## Troubleshooting

| Symptom | Likely cause | Recommended response |
| --- | --- | --- |
| `No targets left` or target parsing error | Input does not match a supported format, or expansion exceeded the ceiling. | Correct the target expression or use an explicitly approved `--max-targets` value. |
| File-descriptor warning | Requested concurrency approaches the process descriptor limit. | Lower `--concurrency`, lower per-host concurrency, or adjust the operating-system limit under approved operational policy. |
| Go engine unavailable | `scanner/lscan` is absent or not executable. | Run `make go`, or pass the correct path with `--go-binary`. |
| Lua checks unavailable | Lua 5.4 runtime is absent or a script failed review/validation. | Install Lua 5.4 and use only reviewed non-destructive checks. |
| Nmap XML import rejected | Input is not a regular Nmap XML file, is malformed, contains DTD/entity declarations, or exceeds the safety limit. | Export a normal local Nmap XML artifact and retry; do not remove the importer’s XML safety guard. |
| No `--os-evidence` result | Service evidence is generic or does not contain a distinctive known signal. | Treat this as intentional abstention rather than a negative OS finding. |

## License

LightScan is released under the [MIT License](LICENSE). Consult each optional dependency’s license before redistributing a packaged environment. Nmap interoperability does not change the license of Nmap, its data files, or any local XML artifacts generated by Nmap.

## References

[1]: https://nmap.org/book/man.html "Nmap Reference Guide"
[2]: https://nmap.org/book/man-os-detection.html "Nmap OS Detection"
[3]: https://nmap.org/book/man-version-detection.html "Nmap Service and Version Detection"
[4]: https://nmap.org/npsl/ "Nmap Public Source License"
[5]: https://nmap.org/book/man-performance.html "Nmap Timing and Performance"

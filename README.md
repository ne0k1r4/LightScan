# LightScan v2.5.0

**LightScan** is an asynchronous network inventory and assessment scanner for systems you own or are explicitly authorized to test. It combines bounded target planning, concurrent TCP discovery, protocol-aware service probing, and structured reports that fit operational workflows.

> **Authorization required.** Network scanning can affect services and generate security alerts. Scan only assets within your written scope, begin with a conservative port set, and use the target limit as a guardrail rather than a substitute for authorization.

## Installation

```bash
git clone https://github.com/ne0k1r4/LightScan.git
cd LightScan
python -m pip install -e .

# Optional modules that need third-party protocol libraries.
python -m pip install -e ".[full]"

# Optional high-concurrency Go companion scanner.
make go

# Optional constrained Lua check runtime (Debian/Ubuntu).
sudo apt-get install lua5.4
```

Python 3.10 or later is required. The core package now declares `PyYAML`, because the bundled template engine depends on it at runtime.

## Recommended workflow

Start with a bounded TCP discovery pass, then enrich **confirmed open ports** with the service probe stage. Combining `--scan` and `--sv` deliberately runs service probes only after discovery, reducing unnecessary application-layer traffic.

```bash
# Inventory a small, authorized subnet and write complete JSON evidence.
lightscan --scan -t 192.0.2.0/28 -p top100 --sv \
  --concurrency 128 --per-host-concurrency 16 --max-rate 250 \
  --retries 1 --retry-jitter 0.15 --host-timeout 10 --format json --output reports

# Scan a reviewed target list; comments and blank lines are allowed.
lightscan --scan -t file:approved-targets.txt -p 22,80,443,3306 \
  --max-targets 256 --stream-open reports/open.ndjson \
  --metrics-out reports/baseline.json --no-report

# Run reviewed, non-destructive Lua checks only after open ports are confirmed.
lightscan --scan -t 192.0.2.10 -p 80,443,8080 \
  --lua-script http-security-headers --format json --output reports

# Stream JSON into another tool without mixing progress messages into stdout.
cat approved-targets.txt | lightscan --scan -t - -p 80,443 --sv \
  --output - --format json | jq '.'
```

| Capability | What it does |
| --- | --- |
| **Bounded target planning** | Expands CIDR, last-octet range, stdin, and `file:` inputs before scanning. The default ceiling is **65,536 targets**; use `--max-targets` to set a smaller approved workload. |
| **Streaming TCP discovery** | Uses a bounded queue rather than creating one coroutine per host-port pair. Global and per-host concurrency, optional rate, transient-aware jittered retry, AIMD feedback, and host-time limits are explicit. |
| **Go execution engine** | Optionally delegates high connection-count TCP discovery to the compiled `lscan` companion, streaming NDJSON back into the same report model. |
| **Incremental results and telemetry** | Streams each open finding to NDJSON without retaining all open ports in memory, writes portable metric snapshots, and records runtime file-descriptor and memory telemetry for repeatable comparisons. |
| **Constrained Lua checks** | Runs only reviewed, non-destructive Lua checks against confirmed open ports. Lua receives a read-only observation context; filesystem, process, module-loading, and network APIs are unavailable. |
| **Service version probing** | Uses protocol-specific handshakes for common services and returns normalized service, version, method, and confidence metadata. |
| **Structured reporting** | Produces JSON, CSV, HTML, minimal text, or Nmap-style XML. JSON preserves the complete result payload, while XML keeps vulnerability findings as script records instead of mislabeling them as ports. |
| **Safe report rendering** | Escapes untrusted network banners in HTML reports to prevent report-viewer injection. |

## Core options

| Option | Description |
| --- | --- |
| `-t, --target` | IP address, CIDR, last-octet range, hostname, `file:targets.txt`, or `-` for stdin. |
| `--max-targets N` | Refuses a target expansion larger than `N`; default: `65536`. |
| `-p, --ports` | Comma-separated ports, ranges such as `1-1024`, or `top100`. Invalid, empty, descending, and out-of-range values are rejected before any scan begins. |
| `--scan` | Run the bounded streaming TCP connect scanner. |
| `--concurrency N` | Maximum concurrent TCP jobs. If omitted, LightScan tunes this against the open-file limit. |
| `--per-host-concurrency N` | Maximum concurrent TCP connections per target; default: `32`. |
| `--host-group-size N` | Host chunk used by the fair streaming producer; default: `256`. |
| `--adaptive` | Uses observed per-host RTT and timeout feedback to adjust the active concurrency window; enabled by default. |
| `--no-adaptive` | Uses the supplied fixed timeout and concurrency controls, useful for reproducible benchmarks. |
| `--max-rate N` | Maximum TCP connection starts per second; `0` disables the explicit cap. |
| `--retries N` | Retry count for timeout, filtered, or transient local-resource outcomes; default: `1`. |
| `--retry-jitter FRACTION` | Randomizes retry backoff by the supplied `0.0`–`1.0` fraction; default: `0.15`. Use `0` for deterministic local benchmark runs. |
| `--host-timeout SECONDS` | Maximum wall-clock time spent on a target; `0` disables the cap. |
| `--no-banner-grab` | Skip application banner reads during discovery. |
| `--stream-open PATH` | Write each open finding immediately as NDJSON and retain only aggregate scan metrics; use `-` for stdout. |
| `--metrics-out PATH` | Write a portable `lightscan-performance/v1` snapshot after a scan. |
| `--compare-metrics BASELINE CANDIDATE` | Compare two v1 metric snapshots offline and exit. |
| `--go-engine` | Use the optional compiled Go TCP execution engine. |
| `--go-binary PATH` | Use a specific `lscan` executable instead of automatic discovery. |
| `--lua-script CHECK` | Run selected constrained Lua checks on confirmed open ports. |
| `--lua-script-tags CATEGORY` | Run constrained Lua checks in selected safe categories. |
| `--lua-script-dir DIR` | Add an explicitly reviewed directory of `.lua` checks. |
| `--list-lua-scripts` | List built-in and explicitly supplied constrained Lua checks without scanning. |
| `--lua-concurrency N` | Limit concurrent Lua observations; default: `10`. |
| `--sv` | Probe services for product and version metadata. With `--scan`, it operates only on confirmed open ports. |
| `--version-concurrency N` | Limit concurrent service probes; default: `20`. |
| `--timeout SECONDS` | Connection and probe timeout; default: `3.0`. |
| `-o, --output PATH` | Output directory, or `-` for stdout. |
| `--format` | `json` (default), `nmap-xml`, `html`, `csv`, or `minimal`. |

## Output contracts

LightScan's **JSON** output retains `target`, `host`, `port`, `status`, `severity`, `detail`, `module`, timestamp, and the result's full `data` evidence object. Legacy `host` and `service` aliases are retained for existing integrations.

The **Nmap-style XML** output includes run metadata, host statistics, port state, service identification method and confidence, and findings represented as `script` elements. This approach mirrors the distinction between port data, probed service attributes, and script output used by Nmap's documented XML format.[1]

## Design scope

LightScan is designed to complement—not claim to replace—mature scanners. Nmap has decades of protocol coverage, raw-packet scan methods, and a broad signature database. LightScan v2.5 focuses on an inspectable Python codebase, predictable target bounds, a bounded streaming scheduler, bracketed-IPv6 normalization, and a compatible optional Go execution engine. Its scheduler classifies temporary local resource pressure separately from filtered outcomes, applies bounded retry jitter to prevent synchronized reattempts, and uses AIMD feedback to reduce concurrency after loss before recovering conservatively. Service identification is inherently probabilistic: a port-number lookup is only a hint, while probe responses provide stronger evidence; Nmap documents the same distinction between table-derived and probe-derived service confidence.[2] Performance is treated as an accuracy problem as well as a throughput problem: Nmap likewise documents that host grouping, timeouts, retries, and rate limits affect scan completeness.[3]

## Development

```bash
python -m pip install -e ".[dev]"
make test
```

The test suite includes local-only regression coverage for target parsing, bracketed IPv6 normalization, port validation, bounded streaming scheduling, transient-aware jittered retries, AIMD behavior, runtime telemetry, retention-free NDJSON results, metric snapshots, constrained Lua checks, rate controls, Go-engine bridging, service probes, report serialization, XML metadata, and HTML escaping. See [PERFORMANCE.md](PERFORMANCE.md), [LUA_CHECKS.md](LUA_CHECKS.md), and [BENCHMARK_65535.md](BENCHMARK_65535.md) for the current architecture, safety contract, and measured local comparison.

## License

Released under the [MIT License](LICENSE).

## References

[1]: https://nmap.org/book/output-formats-xml-output.html "Nmap XML Output"
[2]: https://nmap.org/book/man-version-detection.html "Nmap Service and Version Detection"
[3]: https://nmap.org/book/man-performance.html "Nmap Timing and Performance"

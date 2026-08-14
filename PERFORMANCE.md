# LightScan v2.2 Performance Architecture

LightScan v2.2 replaces the eager Python `hosts × ports` coroutine construction path with a **bounded streaming scheduler**. The objective is not unrestricted packet generation; it is to retain reliable, reviewable inventory results as workload size grows.

> **Design principle:** Speed without loss and timeout feedback is not a dependable security scan. The scheduler treats response latency, failures, retries, and explicit operator limits as execution inputs rather than afterthoughts.[1]

## Execution model

| Layer | Responsibility | Bounded behavior |
| --- | --- | --- |
| Target planner | Expands and de-duplicates approved targets before network activity. | `--max-targets` defaults to 65,536. |
| Streaming scheduler | Produces jobs incrementally instead of allocating every task at once. | Queue capacity is `2 × concurrency`; memory does not scale with the complete host-port Cartesian product. |
| Global control | Limits total in-flight work and optional connection-start rate. | `--concurrency` and `--max-rate` are explicit. |
| Adaptive window | Tracks successful RTTs and timeout feedback per host, then adjusts the active in-flight ceiling. | Enabled by default; `--no-adaptive` fixes the requested timeout and concurrency for benchmark repeatability. |
| Per-host control | Prevents a single device from consuming the scan budget. | `--per-host-concurrency` and `--host-timeout` are explicit. |
| Retry classifier | Retries timeout/filtered outcomes with bounded backoff, but not clear refusals. | `--retries` defaults to `1`. |
| Protocol enrichment | Runs only after TCP discovery identifies an open port. | `--scan --sv` avoids probing closed ports. |
| Go companion | Executes the same bounded TCP-connect contract for high connection counts. | NDJSON is streamed into the Python report model, followed by a compact completion summary. |
| Result stream | Emits each confirmed open finding immediately without retaining it in the scanner result list. | `--stream-open PATH` writes newline-delimited result events followed by one summary event. |
| Metric snapshot | Captures comparable attempt, outcome, retry, elapsed-time, and derived-rate data. | `--metrics-out PATH` writes `lightscan-performance/v1`; `--compare-metrics` compares two snapshots offline. |
| Lua enrichment | Evaluates custom, non-destructive logic only after discovery supplies an open-port list. | See `LUA_CHECKS.md`; retention-free streams intentionally cannot feed Lua checks. |

Port-major host groups spread early work across the scope. This prevents one slow host from monopolizing the queue and corresponds to the general benefit of host-and-port parallelism documented by Nmap.[2]

## Operator controls

| Control | Default | Effect |
| --- | ---: | --- |
| `--max-targets` | `65536` | Refuses an unintended large target expansion before scanning. |
| `--concurrency` | Auto-tuned | Caps all concurrent TCP jobs. |
| `--per-host-concurrency` | `32` | Caps simultaneous TCP connections to one host. |
| `--host-group-size` | `256` | Defines the scope chunk used by the fair job producer. |
| `--adaptive` / `--no-adaptive` | On / Off | Uses per-host RTT and timeout feedback to adjust the active concurrency window, or locks the explicit controls for reproducible runs. |
| `--max-rate` | `0` | Caps connection starts per second; zero means no explicit rate cap. |
| `--retries` | `1` | Limits retry attempts for timeout/filtered outcomes. |
| `--host-timeout` | `0` | Bounds wall-clock time per target; zero disables the limit. |
| `--go-engine` | Off | Selects the compiled Go TCP engine. |
| `--go-binary PATH` | Auto-discovery | Uses a specified `lscan` executable. |
| `--no-banner-grab` | Off | Skips application banner reads during discovery. |

For an approved local environment, begin with a conservative workload and measure the result before changing more than one control:

```bash
lightscan --scan -t file:approved-targets.txt -p top100 \
  --max-targets 512 --concurrency 128 --per-host-concurrency 16 \
  --max-rate 250 --retries 1 --host-timeout 10 --sv --format json
```

The optional Go path uses the same input ceiling, port specification, retry count, host timeout, rate cap, and per-host connection ceiling:

```bash
make go
lightscan --scan --go-engine --go-binary scanner/lscan \
  -t file:approved-targets.txt -p 22,80,443,3306 \
  --max-targets 512 --concurrency 1000 --per-host-concurrency 32 \
  --max-rate 500 --retries 1 --host-timeout 10 --format nmap-xml
```

## Implementation boundaries

The streaming path is a **TCP connect scanner**. It deliberately does not add new evasion, spoofing, brute-force, or exploitation features. Connect outcomes identify open services reliably enough for inventory use, while subsequent service probing captures stronger product/version evidence.

The Go engine uses NDJSON as a narrow process boundary. Python retains ownership of severity assignment, reports, and service-version enrichment, so selecting a faster execution engine does not fork the user-facing result schema.

## Incremental output and telemetry

For scopes where retaining all open findings is undesirable, pair the scanner with an NDJSON event stream:

```bash
lightscan --scan -t file:approved-targets.txt -p top100 \
  --stream-open reports/open.ndjson --metrics-out reports/run-a.json --no-report
```

Each `result` line contains the established LightScan JSON result object. The final `summary` line contains scan metadata and performance data. The Go engine follows the same model internally and sends a single compact completion event back to the Python bridge, allowing aggregate outcomes to remain visible even when non-open port lines are suppressed.

A controlled comparison is then offline and does not perform any network action:

```bash
lightscan --compare-metrics reports/run-a.json reports/run-b.json
```

The comparison includes absolute and relative changes for attempts, outcomes, retries, elapsed time, attempts per second, and result rates. Compare only runs with equivalent target scope, port specification, timeout, banner behavior, and retry policy.

## Benchmarking correctly

Benchmark only on systems you own or are authorized to test. Record the host and port counts, timeout, retry count, rate cap, banner setting, elapsed time, scan metrics, and open-result count. Compare equivalent commands; a lower elapsed time produced by disabling retries or banners is not an apples-to-apples accuracy comparison.

| Measurement | Why it matters |
| --- | --- |
| Job count and queue bound | Confirms that memory is proportional to active work rather than total scope size. |
| Attempts, retries, and filtered outcomes | Distinguishes a fast complete run from a fast run with dropped work. |
| Open-result count | Provides a consistency check between execution engines. |
| Elapsed time and connection-start rate | Quantifies throughput while respecting an operator-defined ceiling. |
| Service-probe duration | Keeps discovery and enrichment costs separate. |

Nmap’s performance documentation similarly emphasizes that timeout, retry, host grouping, parallelism, and rate settings affect both scan duration and accuracy.[1] Its scan-engine documentation further explains why per-host feedback and controlled retransmission are preferable to stateless flooding.[2]

## Measured local comparison

The controlled three-engine comparison of ports `1–65535` on local loopback found median durations of **2.556 s** for LightScan Python, **0.357 s** for the LightScan Go companion, and **0.375 s** for Nmap `-sT` under fixed 1,024-way parallelism. The Go result was in the same performance class as Nmap on this narrow workload; the Python engine was 6.82× slower. See [BENCHMARK_65535.md](BENCHMARK_65535.md) for exact commands, raw trials, and important limits on interpretation.

## Next research increments

The v2.4 foundation supports future work without changing the CLI contract. The next steps are to add RTT estimators per host and scope group, dynamic worker windows that react to measured loss, IPv6-aware Go target expansion, a reusable benchmark harness, and optionally a privileged raw-packet engine for users who explicitly need it. Each should preserve the same limits, metrics, and evidence schema before being exposed as a production mode.

## References

[1]: https://nmap.org/book/man-performance.html "Nmap Timing and Performance"
[2]: https://nmap.org/book/port-scanning-algorithms.html "Nmap Scan Code and Algorithms"

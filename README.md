# LightScan

**LightScan** is an asynchronous network inventory scanner for authorized asset discovery and assessment. Its primary path performs bounded TCP connection scans, optional service observation, and structured reporting. An optional Go engine provides the same core TCP scan controls.

---

## Key Features

- **Streaming TCP discovery**: Bounded scheduling with connection-start rate limits (`--max-rate`) and optional host timeouts.
- **Optional Go engine**: A separate implementation of the bounded TCP connect scan.
- **Scan controls**: Per-host concurrency limits, retries, and an expanded-target ceiling.
- **Local benchmark**: A loopback benchmark records behavior on one test environment; results are not a general performance guarantee.
- **📋 Multi-Format Reporting**: Export results to JSON, CSV, HTML, NDJSON, and Nmap-style XML.
- **🔌 Nmap Evidence Interoperability**: Offline import of Nmap XML results with passive OS family inference.

---

## Performance Benchmark

![Benchmark Results](https://raw.githubusercontent.com/ne0k1r4/LightScan/main/benchmark_results/loopback_65535_v26_chart.png)

---

## Quick Start

### Installation

```bash
git clone https://github.com/ne0k1r4/LightScan.git
cd LightScan
python -m pip install -e .
```

*(Optional)* Build the Go Companion Engine:
```bash
make go
```

### Basic Usage

**Run a bounded TCP scan:**
```bash
lightscan --scan -t 192.0.2.0/28 -p top100 --format json --output reports
```

Focused command forms are available alongside the existing options:
```bash
lightscan scan 192.0.2.0/28 -p top100
lightscan services 192.0.2.10 -p 22,80,443
lightscan web https://example.test
lightscan dns example.test
lightscan report reports/lightscan_report.json --format html --output reports
```

**Run with service observation (`--sv`) and the Go engine:**
```bash
lightscan --scan --go-engine --go-binary scanner/lscan -t 192.0.2.0/28 -p 22,80,443 --sv --format json
```

---

## CLI Options Overview

| Option | Description |
| --- | --- |
| `-t, --target` | Target IP, CIDR, hostname, or `file:targets.txt` |
| `-p, --ports` | Target ports (e.g. `top100`, `22,80,443`, `1-1024`) |
| `--scan` | Enable streaming TCP connect discovery |
| `--sv` | Observe service versions on open ports |
| `--os-evidence` | Infer OS family passively from service evidence |
| `--go-engine` | Use high-performance Go companion scanner |
| `--max-rate N` | Cap connection start rate per second |
| `--concurrency N` | Maximum concurrent TCP connection jobs |
| `--format FORMAT` | Output format (`json`, `html`, `csv`, `minimal`, `nmap-xml`) |

---

## Testing & Verification

Run the automated test suite:
```bash
make test
```

---

## License

Released under the [MIT License](LICENSE).

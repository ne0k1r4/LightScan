# LightScan

**LightScan** is a high-performance, asynchronous TCP inventory and network assessment scanner written in Python with an optional compiled Go engine (`lscan`). Designed for defensive asset discovery and security assessment, it delivers fast, rate-bounded target scanning with structured multi-format reporting.

---

## Key Features

- **⚡ Streaming TCP Discovery**: Bounded producer/consumer model supporting high concurrency, connection rate-limiting (`--max-rate`), and host timeouts.
- **🚀 Go Companion Acceleration**: Built-in Go engine (`lscan`) for high-concurrency TCP scanning workflows.
- **🛡️ Safety & Rate Controls**: Configurable per-host concurrency limits, adaptive backoff, and strict target expansion ceilings.
- **📊 Benchmark Performance**: Bounded local loopback comparison demonstrating high-efficiency scan capabilities.
- **📋 Multi-Format Reporting**: Export results to JSON, CSV, HTML, NDJSON, and Nmap-style XML.
- **🔌 Nmap Evidence Interoperability**: Offline import of Nmap XML results with passive OS family inference.

---

## Performance Benchmark

![Benchmark Results](benchmark_results/loopback_65535_v26_chart.png)

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

**Run with Service Version Detection (`--sv`) and Go Engine:**
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

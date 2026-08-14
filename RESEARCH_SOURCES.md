# External Design References

LightScan’s v2.2 and v2.3 performance architecture was informed by the following official Nmap documentation. These sources are retained as design references rather than copied implementation specifications.

| Topic | Key takeaway applied in LightScan | Source |
| --- | --- | --- |
| Timing and performance | Parallelism, host grouping, timeout, retry, and rate controls must be balanced against scan accuracy. | [Nmap Timing and Performance](https://nmap.org/book/man-performance.html) |
| Scan algorithms | Per-host feedback, RTT estimation, loss awareness, and controlled retransmission are preferable to stateless flooding. | [Nmap Scan Code and Algorithms](https://nmap.org/book/port-scanning-algorithms.html) |
| Service detection | Probe-derived service metadata is stronger evidence than port-number lookup alone. | [Nmap Service and Version Detection](https://nmap.org/book/man-version-detection.html) |
| XML output | Machine-readable output should preserve host, port, service, method, confidence, script, and run-statistics structure. | [Nmap XML Output](https://nmap.org/book/output-formats-xml-output.html) |
| Output formats | Structured output is intended for programmatic consumption and integration. | [Nmap Output Formats](https://nmap.org/book/output.html) |
| NSE categories and safety | NSE offers categories and service-script rules but does not sandbox third-party scripts; LightScan’s Lua extension deliberately permits only non-destructive categories and a read-only context. | [Nmap Scripting Engine](https://nmap.org/book/man-nse.html) |
| TCP connect scan | A fair unprivileged comparison uses a high-level TCP-connect model rather than comparing an async connect scanner with a raw SYN scanner. | [Nmap TCP Connect Scan](https://nmap.org/book/scan-methods-connect-scan.html) |

> These references support the design choices documented in `PERFORMANCE.md`. LightScan remains an independent implementation with an authorized-network inventory focus.

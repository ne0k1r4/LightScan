# Python and Go TCP engine behavior

This document defines the behavior expected from both implementations of the
bounded TCP connect scan. It describes the common subset; features outside
this list remain Python-only unless explicitly implemented and reviewed in Go.

## Inputs and scheduling

- Targets and ports are validated before scanning. Expanded target count is
  bounded by `--max-targets`; duplicate targets preserve first-seen order,
  while duplicate ports are removed and the final port list is numeric-sorted.
- A job is one `(host, port)` pair. Open results are emitted as findings;
  closed, filtered, transient, and skipped outcomes contribute to metrics.
- `--concurrency` bounds in-flight work across the scan. The per-host limit
  bounds in-flight work for each target independently.

## Timing controls

- `--max-rate N` means at most N connection attempts start per second across
  one scanner process. Zero disables the start-rate cap.
- The rate gate spaces attempt start times using a monotonic clock. It does not
  limit completed connections per second and is independent of concurrency.
- The connection timeout bounds an individual connect attempt. The optional
  host timeout bounds total work for one host. Retries count as additional
  attempts and use bounded exponential delay; jitter changes the delay only.
- Cancellation or process termination may leave a final scheduled interval
  unused. No guarantee is made about coordination between separate processes.
- Cancelling a Python scan cancels its worker tasks and abandons queued jobs;
  metrics distinguish scheduled jobs from connection attempts. The Go process
  currently treats interruption as process termination rather than exposing a
  matching in-process cancellation API.

## Result mapping

Both engines return open TCP findings with host, port, status, and optional
banner. The Python adapter maps Go output into `ScanResult` and marks the
method as `go-connect`. Metrics distinguish scheduled jobs from attempts so
retries do not increase the scheduled count.

When changing either engine, update this contract and add equivalent local
fixtures for the changed behavior. Do not infer parity for Python-only
features from the shared TCP contract.

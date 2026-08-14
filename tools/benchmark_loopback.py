#!/usr/bin/env python3
"""Benchmark equivalent local TCP-connect scans on 127.0.0.1 only.

The harness deliberately refuses arbitrary targets. It is intended to compare
scanner execution overhead against the same closed-loopback port range, not to
measure internet or third-party network performance.
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path


PORT_RANGE = "1-65535"
LOOPBACK_TARGET = "127.0.0.1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=3, help="Trials per engine (default: 3)")
    parser.add_argument("--concurrency", type=int, default=1024, help="Fixed parallelism for both engines")
    parser.add_argument("--timeout", type=float, default=1.0, help="TCP connect timeout in seconds")
    parser.add_argument(
        "--go-binary",
        default="scanner/lscan",
        help="Compiled LightScan Go scanner relative to the repository root",
    )
    parser.add_argument(
        "--output",
        default="benchmark_results/loopback_65535.json",
        help="Output JSON path",
    )
    return parser.parse_args()


def run_command(command: list[str], timeout: float) -> dict:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - started
    return {
        "command": command,
        "elapsed_seconds": round(elapsed, 6),
        "returncode": completed.returncode,
        "stderr_tail": completed.stderr[-500:],
    }


def summarize(trials: list[dict]) -> dict:
    elapsed = [trial["elapsed_seconds"] for trial in trials]
    return {
        "trials": trials,
        "median_seconds": round(statistics.median(elapsed), 6),
        "minimum_seconds": round(min(elapsed), 6),
        "maximum_seconds": round(max(elapsed), 6),
        "ports_per_second_median": round(65535 / statistics.median(elapsed), 3),
    }


def main() -> int:
    args = parse_args()
    if args.trials < 1 or args.concurrency < 1 or args.timeout <= 0:
        raise SystemExit("trials, concurrency, and timeout must be positive")
    if not shutil.which("nmap"):
        raise SystemExit("nmap is required for the comparison")
    repository_root = Path(__file__).resolve().parents[1]
    go_binary = (repository_root / args.go_binary).resolve()
    if not go_binary.is_file() or not go_binary.stat().st_mode & 0o111:
        raise SystemExit(f"compiled Go scanner is required at {go_binary}; run `make go` first")

    lightscan_command = [
        sys.executable,
        "-m",
        "lightscan",
        "--no-banner",
        "--scan",
        "-t",
        LOOPBACK_TARGET,
        "-p",
        PORT_RANGE,
        "--concurrency",
        str(args.concurrency),
        "--per-host-concurrency",
        str(args.concurrency),
        "--timeout",
        str(args.timeout),
        "--retries",
        "0",
        "--no-adaptive",
        "--no-banner-grab",
        "--no-report",
    ]
    go_command = [
        str(go_binary),
        "-t",
        LOOPBACK_TARGET,
        "-p",
        PORT_RANGE,
        "-c",
        str(args.concurrency),
        "--per-host-concurrency",
        str(args.concurrency),
        "-T",
        str(max(1, round(args.timeout * 1000))),
        "--retries",
        "0",
        "--no-banner",
        "--open",
        "--json",
        "--summary",
    ]
    nmap_command = [
        "nmap",
        "-sT",
        "-Pn",
        "-n",
        "--max-retries",
        "0",
        "--min-parallelism",
        str(args.concurrency),
        "--max-parallelism",
        str(args.concurrency),
        "--host-timeout",
        "60s",
        "-p",
        PORT_RANGE,
        LOOPBACK_TARGET,
    ]

    lightscan_trials = [run_command(lightscan_command, timeout=180.0) for _ in range(args.trials)]
    go_trials = [run_command(go_command, timeout=180.0) for _ in range(args.trials)]
    nmap_trials = [run_command(nmap_command, timeout=180.0) for _ in range(args.trials)]
    if any(trial["returncode"] != 0 for trial in lightscan_trials + go_trials + nmap_trials):
        raise SystemExit("a benchmark command failed; inspect the saved trial stderr")

    lightscan_summary = summarize(lightscan_trials)
    go_summary = summarize(go_trials)
    nmap_summary = summarize(nmap_trials)
    python_ratio = lightscan_summary["median_seconds"] / nmap_summary["median_seconds"]
    go_ratio = go_summary["median_seconds"] / nmap_summary["median_seconds"]
    document = {
        "schema": "lightscan-loopback-benchmark/v1",
        "scope": {
            "target": LOOPBACK_TARGET,
            "ports": PORT_RANGE,
            "scan_type": "TCP connect",
            "remote_network_traffic": False,
        },
        "controls": {
            "trials": args.trials,
            "concurrency": args.concurrency,
            "timeout_seconds": args.timeout,
            "retries": 0,
            "banner_grab": False,
        },
        "lightscan_python": lightscan_summary,
        "lightscan_go": go_summary,
        "nmap": nmap_summary,
        "comparison": {
            "python_to_nmap_median_time_ratio": round(python_ratio, 4),
            "go_to_nmap_median_time_ratio": round(go_ratio, 4),
            "python_to_go_median_time_ratio": round(
                lightscan_summary["median_seconds"] / go_summary["median_seconds"], 4
            ),
            "python_minus_nmap_median_seconds": round(
                lightscan_summary["median_seconds"] - nmap_summary["median_seconds"], 6
            ),
            "go_minus_nmap_median_seconds": round(
                go_summary["median_seconds"] - nmap_summary["median_seconds"], 6
            ),
        },
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(document["comparison"], indent=2))
    print(f"Saved local benchmark: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

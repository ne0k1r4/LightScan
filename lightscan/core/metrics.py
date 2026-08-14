"""Portable performance telemetry snapshots and comparisons."""
from __future__ import annotations

import json
from pathlib import Path


COUNTERS = (
    "scheduled",
    "attempts",
    "open",
    "closed",
    "filtered",
    "errors",
    "retries",
    "skipped",
    "elapsed",
)


def build_snapshot(performance: dict, meta: dict) -> dict:
    """Create a stable telemetry document from a completed scan performance block."""
    metrics = dict(performance.get("metrics") or {})
    elapsed = float(metrics.get("elapsed") or 0.0)
    attempts = int(metrics.get("attempts") or 0)
    open_count = int(metrics.get("open") or 0)
    filtered = int(metrics.get("filtered") or 0)
    retries = int(metrics.get("retries") or 0)

    return {
        "schema": "lightscan-performance/v1",
        "scan": {
            "target": meta.get("target", ""),
            "engine": performance.get("engine", "unknown"),
            "controls": performance.get("controls", {}),
        },
        "metrics": {key: metrics.get(key, 0) for key in COUNTERS},
        "derived": {
            "attempts_per_second": round(attempts / elapsed, 3) if elapsed else 0.0,
            "open_rate": round(open_count / attempts, 5) if attempts else 0.0,
            "filtered_rate": round(filtered / attempts, 5) if attempts else 0.0,
            "retry_rate": round(retries / attempts, 5) if attempts else 0.0,
        },
    }


def write_snapshot(path: str, performance: dict, meta: dict) -> str:
    """Write a formatted performance snapshot and return the destination path."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(build_snapshot(performance, meta), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return str(destination)


def load_snapshot(path: str) -> dict:
    with Path(path).expanduser().open(encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("schema") != "lightscan-performance/v1":
        raise ValueError(f"{path} is not a LightScan performance snapshot")
    return document


def compare_snapshots(baseline_path: str, candidate_path: str) -> dict:
    """Compare two compatible snapshots using absolute and relative deltas."""
    baseline = load_snapshot(baseline_path)
    candidate = load_snapshot(candidate_path)
    comparison: dict[str, dict] = {}

    for key in COUNTERS:
        old_value = float(baseline["metrics"].get(key, 0) or 0)
        new_value = float(candidate["metrics"].get(key, 0) or 0)
        difference = new_value - old_value
        comparison[key] = {
            "baseline": old_value,
            "candidate": new_value,
            "absolute_change": difference,
            "relative_change": round(difference / old_value, 5) if old_value else None,
        }

    for key in ("attempts_per_second", "open_rate", "filtered_rate", "retry_rate"):
        old_value = float(baseline["derived"].get(key, 0) or 0)
        new_value = float(candidate["derived"].get(key, 0) or 0)
        difference = new_value - old_value
        comparison[key] = {
            "baseline": old_value,
            "candidate": new_value,
            "absolute_change": round(difference, 5),
            "relative_change": round(difference / old_value, 5) if old_value else None,
        }

    return {
        "schema": "lightscan-performance-comparison/v1",
        "baseline": baseline_path,
        "candidate": candidate_path,
        "comparison": comparison,
    }

"""Re-export a LightScan JSON report in another supported format."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from lightscan.core.models import ScanResult, Severity
from lightscan.core.reporter import Reporter


def _load_report(path: str) -> tuple[list[ScanResult], dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("expected a LightScan JSON report with a results array")
    meta = payload.get("meta", {})
    if not isinstance(meta, dict):
        raise ValueError("report meta must be an object")

    results = []
    for index, row in enumerate(payload["results"]):
        if not isinstance(row, dict):
            raise ValueError(f"result {index} must be an object")
        try:
            results.append(
                ScanResult(
                    module=str(row["module"]),
                    target=str(row.get("target", row.get("host", ""))),
                    port=int(row.get("port", 0)),
                    status=str(row["status"]),
                    severity=Severity(str(row.get("severity", "INFO")).upper()),
                    detail=str(row.get("detail", "")),
                    data=row.get("data", {}) if isinstance(row.get("data", {}), dict) else {},
                    timestamp=float(row.get("timestamp", 0.0)),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid result at index {index}: {exc}") from exc
    return results, meta


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="lightscan report")
    parser.add_argument("input", help="LightScan JSON report")
    parser.add_argument("--format", choices=["json", "html", "csv", "nmap-xml", "minimal"], default="json")
    parser.add_argument("--output", default=".", help="Output directory")
    parser.add_argument("--basename", default="lightscan_report")
    args = parser.parse_args(argv)
    try:
        results, meta = _load_report(args.input)
        Reporter(args.output).save(results, meta, args.basename, fmt=args.format)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    return 0

# core/reporter.py — v0.4 JSON + text reporter
# Light
from __future__ import annotations
import json
import os
import time
from lightscan.core.engine import ScanResult


class Reporter:
    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir

    def save(self, results: list[ScanResult], meta: dict, basename: str = "lightscan_report"):
        os.makedirs(self.output_dir, exist_ok=True)
        ts   = int(time.time())
        path = os.path.join(self.output_dir, f"{basename}_{ts}.json")
        data = {
            "meta":    meta,
            "results": [
                {
                    "host":     r.host,
                    "port":     r.port,
                    "service":  r.service,
                    "severity": r.severity.value,
                    "detail":   r.detail,
                    "module":   r.module,
                }
                for r in results
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Report saved: {path}")
        return path

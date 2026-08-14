"""Incremental NDJSON output for high-scale scan findings."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from lightscan.core.engine import ScanResult
from lightscan.core.reporter import Reporter


class NDJSONResultWriter:
    """Write results as newline-delimited events without retaining a result list."""

    def __init__(self, path: str, meta: dict):
        if path == "-":
            import sys

            self._handle: TextIO = sys.__stdout__
            self.path = "-"
        else:
            destination = Path(path).expanduser()
            destination.parent.mkdir(parents=True, exist_ok=True)
            self._handle = destination.open("w", encoding="utf-8")
            self.path = str(destination)
        self._meta = meta
        self._closed = False

    def emit(self, result: ScanResult) -> None:
        if self._closed:
            raise RuntimeError("cannot write a result after the NDJSON stream has closed")
        self._write({"type": "result", "result": Reporter._json_result(result)})

    def close(self, performance: dict) -> None:
        if self._closed:
            return
        self._write(
            {
                "type": "summary",
                "meta": self._meta,
                "performance": performance,
            }
        )
        if self.path != "-":
            self._handle.close()
        self._closed = True

    def _write(self, event: dict) -> None:
        self._handle.write(json.dumps(event, sort_keys=True) + "\n")
        self._handle.flush()

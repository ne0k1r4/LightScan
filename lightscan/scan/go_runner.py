"""Optional bridge to the LightScan Go TCP connect scanner."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable, Sequence

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import CRIT_PORTS, HIGH_PORTS, SERVICE_MAP
from lightscan.scan.streaming import ScanControls


class GoScannerError(RuntimeError):
    """Raised when the optional Go scanner cannot complete a requested run."""


def find_go_scanner(explicit_path: str | None = None) -> str | None:
    """Locate an explicitly supplied binary, a PATH entry, or the bundled build."""
    candidates: list[Path] = []
    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())

    path_binary = shutil.which("lscan")
    if path_binary:
        candidates.append(Path(path_binary))

    bundled = Path(__file__).resolve().parents[2] / "scanner" / "lscan"
    candidates.append(bundled)

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


async def scan_with_go(
    hosts: Sequence[str],
    ports: Sequence[int],
    *,
    timeout: float,
    controls: ScanControls,
    banners: bool = True,
    binary_path: str | None = None,
    result_sink: Callable[[ScanResult], None] | None = None,
    retain_results: bool = True,
) -> tuple[list[ScanResult], dict]:
    """Stream NDJSON from Go into LightScan's common result representation."""
    binary = find_go_scanner(binary_path)
    if not binary:
        raise GoScannerError(
            "Go scan engine was requested but lscan was not found. "
            "Build it with `make go` or pass --go-binary /path/to/lscan."
        )

    target_file = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="lightscan-targets-", delete=False
    )
    try:
        target_file.write("\n".join(hosts))
        target_file.write("\n")
        target_file.close()

        command = [
            binary,
            "-t", f"file:{target_file.name}",
            "-p", ",".join(str(port) for port in ports),
            "-c", str(controls.concurrency),
            "--per-host-concurrency", str(controls.per_host_concurrency),
            "--max-targets", str(len(hosts)),
            "--retries", str(controls.retries),
            "--host-timeout", f"{controls.host_timeout}s",
            "--max-rate", str(controls.max_rate),
            "-T", str(max(1, round(timeout * 1000))),
            "--json",
            "--summary",
            "--open",
        ]
        if not banners:
            command.append("--no-banner")

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        findings: list[ScanResult] = []
        open_results = 0
        malformed_lines = 0
        aggregate_metrics: dict = {}

        assert process.stdout is not None
        async for raw_line in process.stdout:
            try:
                record = json.loads(raw_line)
                if record.get("type") == "summary":
                    aggregate_metrics = dict(record.get("metrics") or {})
                    aggregate_metrics["elapsed"] = record.get("elapsed", 0.0)
                    continue
                if record.get("status") != "open":
                    continue
                port = int(record["port"])
                service = SERVICE_MAP.get(port, f"port/{port}")
                banner = str(record.get("banner", ""))[:200]
                severity = (
                    Severity.CRITICAL if port in CRIT_PORTS
                    else Severity.HIGH if port in HIGH_PORTS
                    else Severity.INFO
                )
                detail = service + (f" | {banner[:80]}" if banner else "")
                finding = ScanResult(
                        "portscan",
                        str(record["host"]),
                        port,
                        "open",
                        severity,
                        detail,
                        {
                            "service": service,
                            "banner": banner,
                            "latency_ms": record.get("ms"),
                            "attempts": record.get("attempts", 1),
                            "method": "go-connect",
                        },
                    )
                open_results += 1
                if result_sink is not None:
                    result_sink(finding)
                if retain_results:
                    findings.append(finding)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                malformed_lines += 1

        stderr = (await process.stderr.read()).decode("utf-8", "replace") if process.stderr else ""
        return_code = await process.wait()
        if return_code != 0:
            detail = stderr.strip() or f"lscan exited with status {return_code}"
            raise GoScannerError(detail)

        metadata = {
            "engine": "go",
            "binary": binary,
            "open_results": open_results,
            "malformed_lines": malformed_lines,
            "metrics": aggregate_metrics,
        }
        return findings, metadata
    finally:
        try:
            os.unlink(target_file.name)
        except OSError:
            pass

"""Tests for v2.3 incremental output and performance telemetry."""
from __future__ import annotations

import asyncio
import json

import pytest

from lightscan.core.engine import ScanResult, Severity
from lightscan.core.metrics import build_snapshot, compare_snapshots, write_snapshot
from lightscan.core.ndjson import NDJSONResultWriter
from lightscan.scan.streaming import ScanControls, StreamingTCPScanner


@pytest.fixture
async def tcp_banner_server():
    async def handler(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_9.8\r\n")
        await writer.drain()
        try:
            await reader.read(64)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


def test_ndjson_writer_emits_results_then_a_summary(tmp_path):
    path = tmp_path / "open.ndjson"
    writer = NDJSONResultWriter(str(path), {"target": "192.0.2.10"})
    writer.emit(
        ScanResult(
            "portscan",
            "192.0.2.10",
            443,
            "open",
            Severity.INFO,
            "HTTPS",
            {"service": "HTTPS"},
        )
    )
    writer.close({"engine": "streaming-python", "metrics": {"attempts": 1, "open": 1}})

    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [event["type"] for event in events] == ["result", "summary"]
    assert events[0]["result"]["host"] == "192.0.2.10"
    assert events[1]["performance"]["metrics"]["open"] == 1


async def test_streaming_scan_can_emit_without_retaining_results(tcp_banner_server):
    emitted = []
    scanner = StreamingTCPScanner(
        ScanControls(concurrency=2, retries=0),
        timeout=0.5,
        result_sink=emitted.append,
    )

    retained = await scanner.scan(["127.0.0.1"], [tcp_banner_server], retain_results=False)

    assert retained == []
    assert len(emitted) == 1
    assert emitted[0].port == tcp_banner_server
    assert scanner.metrics.open == 1


def test_metric_snapshots_capture_derived_rates_and_compare(tmp_path):
    baseline_performance = {
        "engine": "streaming-python",
        "controls": {"concurrency": 32},
        "metrics": {"scheduled": 100, "attempts": 100, "open": 10, "elapsed": 10.0},
    }
    candidate_performance = {
        "engine": "go",
        "controls": {"concurrency": 256},
        "metrics": {"scheduled": 100, "attempts": 100, "open": 10, "elapsed": 5.0},
    }
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"

    write_snapshot(str(baseline), baseline_performance, {"target": "192.0.2.0/28"})
    write_snapshot(str(candidate), candidate_performance, {"target": "192.0.2.0/28"})
    comparison = compare_snapshots(str(baseline), str(candidate))

    assert build_snapshot(baseline_performance, {"target": "x"})["derived"]["attempts_per_second"] == 10.0
    assert comparison["comparison"]["elapsed"]["absolute_change"] == -5.0
    assert comparison["comparison"]["attempts_per_second"]["absolute_change"] == 10.0

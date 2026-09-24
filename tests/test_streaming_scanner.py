"""Local-only regression coverage for the high-scale TCP scan architecture."""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from lightscan.scan.go_runner import scan_with_go
from lightscan.core.rate_limit import RateLimiter
from lightscan.scan.streaming import ScanControls, StreamingTCPScanner, _RateGate

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

def test_scan_controls_reject_invalid_capacity_values():
    with pytest.raises(ValueError, match="concurrency"):
        ScanControls(concurrency=0)
    with pytest.raises(ValueError, match="per_host"):
        ScanControls(per_host_concurrency=0)
    with pytest.raises(ValueError, match="retries"):
        ScanControls(retries=-1)
    with pytest.raises(ValueError, match="finite"):
        ScanControls(max_rate=float("nan"))

def test_job_iterator_interleaves_hosts_before_advancing_to_next_port():
    scanner = StreamingTCPScanner(ScanControls(host_group_size=2), banners=False)

    jobs = list(scanner._iter_jobs(["a", "b", "c"], [80, 443]))

    assert [(job.host, job.port) for job in jobs] == [
        ("a", 80), ("b", 80), ("c", 80),
        ("a", 443), ("b", 443), ("c", 443),
    ]

async def test_streaming_scanner_reports_only_open_ports_and_tracks_all_attempts(tcp_banner_server):
    closed_port = tcp_banner_server + 1
    scanner = StreamingTCPScanner(
        ScanControls(concurrency=4, per_host_concurrency=1, retries=0),
        timeout=0.5,
        banners=True,
    )

    findings = await scanner.scan(["127.0.0.1"], [tcp_banner_server, closed_port])

    assert len(findings) == 1
    assert findings[0].port == tcp_banner_server
    assert findings[0].data["method"] == "connect"
    assert "OpenSSH_9.8" in findings[0].data["banner"]
    assert scanner.metrics.scheduled == 2
    assert scanner.metrics.attempts == 2
    assert scanner.metrics.open == 1
    assert scanner.metrics.closed == 1
    assert scanner.adaptive_summary is not None
    assert "sent=2" in scanner.adaptive_summary

async def test_rate_gate_spaces_connection_starts():
    gate = _RateGate(max_rate=25)
    started = asyncio.get_running_loop().time()
    await gate.wait()
    await gate.wait()
    await gate.wait()
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed >= 0.06

async def test_cancelling_scan_stops_workers_without_draining_pending_jobs():
    scanner = StreamingTCPScanner(
        ScanControls(concurrency=1, per_host_concurrency=1, adaptive=False),
        banners=False,
    )
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def blocked_job(_job):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    scanner._scan_job = blocked_job
    scan_task = asyncio.create_task(
        scanner.scan(["192.0.2.1"], [80, 443, 8080, 8443])
    )
    await asyncio.wait_for(started.wait(), timeout=1)
    scan_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(scan_task, timeout=1)
    assert stopped.is_set()
    assert scanner.metrics.scheduled < 4

async def test_shared_rate_limiter_spaces_acquires_at_starts_per_second():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "engine_inputs.json").read_text()
    )
    limiter = RateLimiter(rate=fixture["max_rate"])
    loop = asyncio.get_running_loop()
    starts = []
    for _ in range(3):
        await limiter.acquire()
        starts.append(loop.time())

    assert starts[1] - starts[0] >= 0.045
    assert (starts[2] - starts[0]) * 1000 >= fixture["min_elapsed_ms_for_three_starts"]

def test_rate_limiter_rejects_negative_rate():
    with pytest.raises(ValueError, match="rate"):
        RateLimiter(rate=-1)

def test_rate_limiter_rejects_non_finite_rate():
    with pytest.raises(ValueError, match="finite"):
        RateLimiter(rate=float("inf"))

@pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain is unavailable")
async def test_go_engine_streams_open_results_into_common_result_contract(tcp_banner_server, tmp_path):
    repository_root = Path(__file__).resolve().parents[1]
    binary = tmp_path / "lscan"
    subprocess.run(
        ["go", "build", "-o", str(binary), "."],
        cwd=repository_root / "scanner",
        check=True,
        capture_output=True,
        text=True,
    )

    findings, metadata = await scan_with_go(
        ["127.0.0.1"],
        [tcp_banner_server],
        timeout=0.5,
        controls=ScanControls(concurrency=8, per_host_concurrency=2, retries=0),
        banners=False,
        binary_path=str(binary),
    )

    assert metadata["engine"] == "go"
    assert metadata["open_results"] == 1
    assert metadata["metrics"]["attempts"] == 1
    assert metadata["metrics"]["open"] == 1
    assert len(findings) == 1
    assert findings[0].port == tcp_banner_server
    assert findings[0].data["method"] == "go-connect"

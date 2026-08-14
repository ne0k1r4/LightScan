"""Local-only regression coverage for the high-scale TCP scan architecture."""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest

from lightscan.scan.go_runner import scan_with_go
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

    # The first permit is immediate; the next two are separated by ~40ms each.
    assert elapsed >= 0.06


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

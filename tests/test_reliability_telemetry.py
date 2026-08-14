"""Regression coverage for retry policy and runtime telemetry."""
from __future__ import annotations

import asyncio

import pytest

from lightscan.core.runtime_telemetry import capture_runtime_snapshot, resource_delta
from lightscan.scan.streaming import ScanControls, StreamingTCPScanner, _Job


@pytest.fixture
async def tcp_banner_server():
    async def handler(reader, writer):
        try:
            await reader.read(32)
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


def test_runtime_snapshot_is_best_effort_and_serializable():
    snapshot = capture_runtime_snapshot()
    payload = snapshot.to_dict()

    assert set(payload) == {
        "open_file_descriptors",
        "fd_soft_limit",
        "fd_hard_limit",
        "max_rss_kib",
    }
    assert all(value is None or isinstance(value, int) for value in payload.values())
    assert resource_delta(snapshot, capture_runtime_snapshot())["fd_soft_limit"] == snapshot.fd_soft_limit


def test_retry_jitter_is_bounded_and_can_be_disabled_for_reproducibility():
    deterministic = StreamingTCPScanner(
        ScanControls(retry_jitter=0), banners=False
    )
    assert deterministic._retry_delay(1) == pytest.approx(0.05)
    assert deterministic._retry_delay(2) == pytest.approx(0.1)

    jittered = StreamingTCPScanner(ScanControls(retry_jitter=0.2), banners=False)
    samples = [jittered._retry_delay(2) for _ in range(20)]
    assert all(0.08 <= delay <= 0.12 for delay in samples)


async def test_transient_outcomes_receive_a_bounded_retry_with_telemetry():
    scanner = StreamingTCPScanner(
        ScanControls(retries=1, retry_jitter=0), banners=False
    )
    outcomes = iter([("transient", None), ("closed", None)])

    async def fake_connect(host: str, port: int):
        return next(outcomes)

    scanner._connect_once = fake_connect  # type: ignore[method-assign]
    result = await scanner._scan_with_retries(_Job("127.0.0.1", 9))

    assert result is None
    assert scanner.metrics.retries == 1
    assert scanner.metrics.retry_transient == 1
    assert scanner.metrics.retry_filtered == 0
    assert scanner.metrics.closed == 1
    assert scanner.metrics.retry_delay_seconds == pytest.approx(0.05)


async def test_completed_scan_records_runtime_telemetry(tcp_banner_server):
    scanner = StreamingTCPScanner(
        ScanControls(concurrency=2, per_host_concurrency=1, retries=0),
        timeout=0.5,
        banners=False,
    )

    await scanner.scan(["127.0.0.1"], [tcp_banner_server])

    assert "fd_soft_limit" in scanner.metrics.runtime
    assert "max_rss_kib" in scanner.metrics.runtime

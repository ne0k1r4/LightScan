"""Regression coverage for loss-aware concurrency and IPv6-ready targeting."""
from __future__ import annotations

import pytest

from lightscan.core.target import TargetSpecError, parse_targets
from lightscan.scan.aimd import AimdConcurrencyController


def test_aimd_halves_on_loss_and_recovers_one_slot_after_stability():
    controller = AimdConcurrencyController(
        initial=16,
        maximum=32,
        minimum=4,
        increase_every=3,
    )

    assert controller.record("filtered") == 8
    assert controller.record("transient") == 4
    assert controller.record("open") == 4
    assert controller.record("closed") == 4
    assert controller.record("open") == 5
    assert controller.summary()["decreases"] == 2
    assert controller.summary()["increases"] == 1


def test_aimd_rejects_invalid_window_configuration():
    with pytest.raises(ValueError, match="minimum"):
        AimdConcurrencyController(initial=1, maximum=4, minimum=0)
    with pytest.raises(ValueError, match="initial"):
        AimdConcurrencyController(initial=8, maximum=4)


def test_target_parser_normalizes_bracketed_ipv6_literals():
    assert parse_targets("[::1]") == ["::1"]
    assert parse_targets("2001:db8::1") == ["2001:db8::1"]


def test_target_parser_preserves_ipv6_cidr_limit_protection():
    assert parse_targets("::1/128") == ["::1"]
    with pytest.raises(TargetSpecError, match="above"):
        parse_targets("2001:db8::/64", max_targets=8)


async def test_streaming_scanner_handles_ipv6_loopback_when_available():
    async def handler(reader, writer):
        writer.close()
        await writer.wait_closed()

    try:
        server = await __import__("asyncio").start_server(handler, "::1", 0)
    except OSError:
        pytest.skip("IPv6 loopback is unavailable in this environment")

    port = server.sockets[0].getsockname()[1]
    try:
        from lightscan.scan.streaming import ScanControls, StreamingTCPScanner

        scanner = StreamingTCPScanner(
            ScanControls(concurrency=2, per_host_concurrency=1, retries=0),
            timeout=0.5,
            banners=False,
        )
        findings = await scanner.scan(["::1"], [port])
        assert len(findings) == 1
        assert findings[0].target == "::1"
    finally:
        server.close()
        await server.wait_closed()

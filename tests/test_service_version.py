"""Local-only tests for protocol-aware service version detection."""
from __future__ import annotations

import asyncio

import pytest

from lightscan.scan.sversion import detect_services, detect_version


@pytest.fixture
async def ssh_banner_server():
    async def handler(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_9.8p1 Debian-1\r\n")
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


async def test_detect_version_reads_an_ssh_banner(ssh_banner_server):
    result = await detect_version("127.0.0.1", ssh_banner_server, timeout=0.5)

    assert result["service"] == "SSH"
    assert result["version"].startswith("OpenSSH_9.8p1")
    assert result["protocol"] == "SSH-2.0"


async def test_detect_services_returns_common_scan_results(ssh_banner_server):
    findings = await detect_services(
        "127.0.0.1",
        [ssh_banner_server],
        timeout=0.5,
        concurrency=1,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.module == "service-version"
    assert finding.port == ssh_banner_server
    assert finding.status == "open"
    assert finding.data["method"] == "probed"
    assert finding.data["confidence"] == 10

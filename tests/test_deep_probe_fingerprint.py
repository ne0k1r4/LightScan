import asyncio

import pytest

import lightscan.scan.active as active_mod
from lightscan.scan.active import deep_probe

_TEST_PORT = 18264

@pytest.fixture
def as_http_port(monkeypatch):
    monkeypatch.setitem(active_mod._PROTO_PROBES, _TEST_PORT, b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
    monkeypatch.setitem(active_mod.SERVICE_MAP, _TEST_PORT, "http")

@pytest.mark.asyncio
async def test_deep_probe_return_shape_always_consistent():
    result = await deep_probe("127.0.0.1", 59999, timeout=1.0)
    assert isinstance(result, dict)
    assert set(result.keys()) == {"service", "banner", "version", "product", "os", "devtype", "info"}

@pytest.mark.asyncio
async def test_deep_probe_extracts_product_through_full_pipeline(as_http_port):
    async def handle(r, w):
        await r.read(200)
        w.write(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n<html></html>")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", _TEST_PORT)
    try:
        result = await deep_probe("127.0.0.1", _TEST_PORT, timeout=3.0)
        assert result["product"] == "nginx"
        assert result["version"] == "1.24.0"
    finally:
        srv.close()

@pytest.mark.asyncio
async def test_deep_probe_ssh_unsolicited_banner():
    port = 18022
    async def handle(r, w):
        w.write(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", port)
    try:
        result = await deep_probe("127.0.0.1", port, timeout=3.0)
        assert result["service"] == "ssh"
        assert result["product"] == "OpenSSH"
        assert "9.6" in result["version"]
    finally:
        srv.close()

@pytest.mark.asyncio
async def test_deep_probe_falls_back_to_old_regex_when_no_signature_matches():
    port = 18021
    async def handle(r, w):
        w.write(b"totally-unknown-service 4.2.1 ready\r\n")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", port)
    try:
        result = await deep_probe("127.0.0.1", port, timeout=3.0)
        assert result["version"]
    finally:
        srv.close()

@pytest.mark.asyncio
async def test_deep_probe_dead_port_no_crash():
    result = await deep_probe("127.0.0.1", 1, timeout=1.0)
    assert isinstance(result, dict)
    assert result["banner"] == ""


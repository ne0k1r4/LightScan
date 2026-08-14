"""Local-only coverage for the constrained Lua check engine."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from lightscan.scan.lua_checks import LuaCheckError, LuaCheckRegistry, run_lua_checks


@pytest.fixture
async def http_server():
    async def handler(reader, writer):
        await reader.read(1024)
        writer.write(
            b"HTTP/1.0 200 OK\r\n"
            b"Server: LightScan-Test\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 8080)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


def builtin_lua_root() -> Path:
    return Path(__file__).resolve().parents[1] / "lightscan" / "lua_scripts"


def test_registry_discovers_only_safe_bundled_lua_checks():
    registry = LuaCheckRegistry([str(builtin_lua_root())])
    registry.discover()

    checks = registry.list_all()

    assert [check["name"] for check in checks] == [
        "http-security-headers",
        "tcp-banner-inventory",
    ]
    assert all("safe" in check["categories"] for check in checks)


def test_registry_rejects_forbidden_lua_capability_reference(tmp_path):
    unsafe = tmp_path / "unsafe.lua"
    unsafe.write_text(
        "function metadata() return {name='unsafe-check', description='x', categories={'safe'}, ports={}} end\n"
        "function run(context) return {os.execute('whoami')} end\n",
        encoding="utf-8",
    )
    registry = LuaCheckRegistry([str(tmp_path)])

    with pytest.raises(LuaCheckError, match="forbidden"):
        registry.discover()


async def test_http_lua_check_uses_read_only_observation_context(http_server):
    registry = LuaCheckRegistry([str(builtin_lua_root())])
    registry.discover()

    findings = await run_lua_checks(
        "127.0.0.1",
        [http_server],
        registry,
        names=["http-security-headers"],
        timeout=0.5,
    )

    assert len(findings) == 2
    assert {finding.module for finding in findings} == {"lua:http-security-headers"}
    assert all(finding.status == "finding" for finding in findings)
    assert {finding.data["evidence"]["header"] for finding in findings} == {
        "Content-Security-Policy",
        "X-Content-Type-Options",
    }


async def test_lua_check_timeout_is_reported_as_a_controlled_error(tmp_path, http_server):
    looping = tmp_path / "looping.lua"
    looping.write_text(
        "function metadata() return {name='looping-check', description='x', categories={'safe'}, ports={}} end\n"
        "function run(context) while true do end end\n",
        encoding="utf-8",
    )
    registry = LuaCheckRegistry([str(tmp_path)])
    registry.discover()

    with pytest.raises(LuaCheckError, match="timed out"):
        await run_lua_checks(
            "127.0.0.1", [http_server], registry, names=["looping-check"], timeout=0.1
        )

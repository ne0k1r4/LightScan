"""Constrained NSE-inspired Lua checks for authorized, non-destructive service review.

Lua scripts receive an immutable observation context collected by LightScan. They
cannot open sockets, read files, spawn processes, or load additional code. A
script may only decide whether it applies and emit declarative findings through
the small ``lightscan`` API defined by the Lua runner.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from lightscan.core.engine import ScanResult, Severity

_SAFE_CATEGORIES = {"default", "discovery", "safe", "version", "vuln"}
_VALID_SEVERITIES = {severity.value.lower(): severity for severity in Severity}
_FORBIDDEN_TOKENS = re.compile(
    r"\b(?:dofile|load|loadfile|require|package|io|os|debug|socket)\b"
)
_HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}


class LuaCheckError(RuntimeError):
    """Raised when a constrained Lua check cannot be safely executed."""


@dataclass(frozen=True)
class LuaCheckMetadata:
    """NSE-inspired metadata produced by a validated Lua check."""

    name: str
    description: str
    categories: tuple[str, ...]
    ports: tuple[int, ...]


@dataclass(frozen=True)
class LuaCheck:
    """A validated Lua source file and its exposed metadata."""

    path: Path
    metadata: LuaCheckMetadata


class LuaCheckRegistry:
    """Discover, validate, and select Lua checks from explicitly supplied roots."""

    def __init__(self, roots: Sequence[str] | None = None, lua_binary: str | None = None):
        self.roots = [Path(root).expanduser().resolve() for root in (roots or [])]
        self.lua_binary = lua_binary or shutil.which("lua")
        self._checks: dict[str, LuaCheck] = {}

    def discover(self) -> None:
        if not self.lua_binary:
            raise LuaCheckError("Lua 5.4 was not found. Install lua5.4 to run Lua checks.")
        for root in self.roots:
            if not root.is_dir():
                continue
            for path in sorted(root.glob("*.lua")):
                check = self._load(path)
                if check.metadata.name in self._checks:
                    raise LuaCheckError(f"duplicate Lua check name: {check.metadata.name}")
                self._checks[check.metadata.name] = check

    def list_all(self) -> list[dict]:
        return [
            {
                "name": check.metadata.name,
                "description": check.metadata.description,
                "categories": list(check.metadata.categories),
                "ports": list(check.metadata.ports),
            }
            for check in sorted(self._checks.values(), key=lambda item: item.metadata.name)
        ]

    def select(self, names: Sequence[str] | None = None, categories: Sequence[str] | None = None) -> list[LuaCheck]:
        checks: Iterable[LuaCheck] = self._checks.values()
        if names:
            requested = set(names)
            missing = requested.difference(self._checks)
            if missing:
                raise LuaCheckError(f"unknown Lua check(s): {', '.join(sorted(missing))}")
            checks = [self._checks[name] for name in names]
        if categories:
            requested_categories = {category.lower() for category in categories}
            checks = [
                check for check in checks
                if requested_categories.intersection(check.metadata.categories)
            ]
        return sorted(checks, key=lambda check: check.metadata.name)

    def _load(self, path: Path) -> LuaCheck:
        source = path.read_text(encoding="utf-8")
        match = _FORBIDDEN_TOKENS.search(source)
        if match:
            raise LuaCheckError(
                f"{path.name}: forbidden Lua capability reference `{match.group(0)}`"
            )
        metadata = self._execute(path, mode="metadata", context={})
        if not isinstance(metadata, dict):
            raise LuaCheckError(f"{path.name}: metadata() must return a table")

        name = str(metadata.get("name", "")).strip()
        description = str(metadata.get("description", "")).strip()
        categories = tuple(str(value).lower() for value in _list_value(metadata.get("categories")))
        ports = tuple(int(value) for value in _list_value(metadata.get("ports")))
        if not name or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", name):
            raise LuaCheckError(f"{path.name}: metadata.name must be a lowercase identifier")
        if not description:
            raise LuaCheckError(f"{path.name}: metadata.description is required")
        if not categories or not set(categories).issubset(_SAFE_CATEGORIES):
            allowed = ", ".join(sorted(_SAFE_CATEGORIES))
            raise LuaCheckError(f"{path.name}: categories must be limited to {allowed}")
        if any(port < 1 or port > 65535 for port in ports):
            raise LuaCheckError(f"{path.name}: ports must be within 1-65535")
        return LuaCheck(path, LuaCheckMetadata(name, description, categories, ports))

    def _execute(self, path: Path, mode: str, context: dict) -> object:
        if not self.lua_binary:
            raise LuaCheckError("Lua 5.4 was not found. Install lua5.4 to run Lua checks.")
        with tempfile.TemporaryDirectory(prefix="lightscan-lua-") as temp_dir:
            context_path = Path(temp_dir) / "context.json"
            context_path.write_text(json.dumps(context, separators=(",", ":")), encoding="utf-8")
            runner = _lua_runner(path, mode, context_path)
            runner_path = Path(temp_dir) / "runner.lua"
            runner_path.write_text(runner, encoding="utf-8")
            try:
                completed = _run_lua(self.lua_binary, runner_path, timeout=2.0)
            except LuaCheckError as exc:
                raise LuaCheckError(f"{path.name}: {exc}") from exc
        try:
            response = json.loads(completed)
        except json.JSONDecodeError as exc:
            raise LuaCheckError(f"{path.name}: invalid Lua response") from exc
        if response.get("ok") is not True:
            raise LuaCheckError(f"{path.name}: {response.get('error', 'Lua execution failed')}")
        return response.get("value")


async def run_lua_checks(
    host: str,
    open_ports: Sequence[int],
    registry: LuaCheckRegistry,
    *,
    names: Sequence[str] | None = None,
    categories: Sequence[str] | None = None,
    timeout: float = 3.0,
    concurrency: int = 10,
) -> list[ScanResult]:
    """Run selected Lua checks against confirmed open ports only."""
    if timeout <= 0 or concurrency < 1:
        raise ValueError("timeout and concurrency must be positive")
    checks = registry.select(names=names, categories=categories)
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    for port in sorted(set(open_ports)):
        for check in checks:
            if check.metadata.ports and port not in check.metadata.ports:
                continue
            tasks.append(_run_one(host, port, check, registry, timeout, semaphore))
    completed = await asyncio.gather(*tasks) if tasks else []
    return [result for group in completed for result in group]


async def _run_one(
    host: str,
    port: int,
    check: LuaCheck,
    registry: LuaCheckRegistry,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> list[ScanResult]:
    async with semaphore:
        context = await _collect_context(host, port, timeout)
        if context is None:
            return []
        output = await asyncio.to_thread(registry._execute, check.path, "run", context)
        if output is None:
            return []
        if not isinstance(output, list):
            raise LuaCheckError(f"{check.metadata.name}: run() must return a table of findings")
        return _normalize_findings(check.metadata, host, port, output)


async def _collect_context(host: str, port: int, timeout: float) -> dict | None:
    """Collect a read-only observation; Lua code never receives a socket."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        payload = b""
        if port in _HTTP_PORTS:
            writer.write(
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii", "ignore")
            )
            await writer.drain()
        try:
            payload = await asyncio.wait_for(reader.read(4096), timeout=min(timeout, 1.5))
        except asyncio.TimeoutError:
            pass
        text = payload.decode("utf-8", errors="replace")
        headers, _, body = text.partition("\r\n\r\n")
        return {
            "host": host,
            "port": port,
            "banner": text[:512],
            "headers": headers[:2048],
            "body_preview": body[:512],
            "protocol_hint": "http" if port in _HTTP_PORTS else "tcp",
        }
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


def _normalize_findings(
    metadata: LuaCheckMetadata,
    host: str,
    port: int,
    findings: list[object],
) -> list[ScanResult]:
    normalized: list[ScanResult] = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise LuaCheckError(f"{metadata.name}: each finding must be a table")
        severity_name = str(finding.get("severity", "info")).lower()
        severity = _VALID_SEVERITIES.get(severity_name)
        if severity is None:
            raise LuaCheckError(f"{metadata.name}: invalid severity {severity_name!r}")
        detail = str(finding.get("detail", "")).strip()
        if not detail or len(detail) > 512:
            raise LuaCheckError(f"{metadata.name}: detail must contain 1-512 characters")
        evidence = finding.get("evidence", {})
        if not isinstance(evidence, dict):
            raise LuaCheckError(f"{metadata.name}: evidence must be a table")
        normalized.append(
            ScanResult(
                f"lua:{metadata.name}",
                host,
                port,
                "finding",
                severity,
                detail,
                {
                    "engine": "lightscan-lua-safe/v1",
                    "categories": list(metadata.categories),
                    "evidence": evidence,
                },
            )
        )
    return normalized


def _list_value(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise LuaCheckError("Lua metadata lists must be JSON arrays")


def _run_lua(binary: str, runner_path: Path, timeout: float) -> str:
    import subprocess

    environment = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    try:
        completed = subprocess.run(
            [binary, str(runner_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(runner_path.parent),
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise LuaCheckError("Lua execution timed out") from exc
    if completed.returncode != 0:
        raise LuaCheckError(completed.stderr.strip() or "Lua runner exited unsuccessfully")
    return completed.stdout


def _lua_runner(script_path: Path, mode: str, context_path: Path) -> str:
    """Build a minimal Lua process that exposes no ambient capabilities."""
    encoded_path = json.dumps(str(script_path))
    encoded_mode = json.dumps(mode)
    encoded_context_path = json.dumps(str(context_path))
    return f'''local source_path = {encoded_path}
local mode = {encoded_mode}
local context_file = assert(io.open({encoded_context_path}, "r"))
local context_json = context_file:read("*a")
context_file:close()

local function escape(value)
  value = tostring(value)
  value = value:gsub([[\\]], [[\\\\]])
  value = value:gsub([["]], [[\\"]])
  value = value:gsub("\\n", [[\\n]])
  value = value:gsub("\\r", [[\\r]])
  return value
end

local function encode(value)
  local kind = type(value)
  if kind == "nil" then return "null" end
  if kind == "boolean" then return value and "true" or "false" end
  if kind == "number" then return tostring(value) end
  if kind == "string" then return '"' .. escape(value) .. '"' end
  if kind ~= "table" then error("unsupported return value") end
  local count, maximum = 0, 0
  for key, _ in pairs(value) do
    if type(key) == "number" and key > maximum and key == math.floor(key) then maximum = key end
    count = count + 1
  end
  if maximum == count then
    local parts = {{}}
    for index = 1, maximum do parts[#parts + 1] = encode(value[index]) end
    return "[" .. table.concat(parts, ",") .. "]"
  end
  local parts = {{}}
  for key, item in pairs(value) do
    if type(key) ~= "string" then error("object keys must be strings") end
    parts[#parts + 1] = encode(key) .. ":" .. encode(item)
  end
  table.sort(parts)
  return "{{" .. table.concat(parts, ",") .. "}}"
end

local function decode_string(source)
  local index = 1
  local function skip() while source:sub(index, index):match("%s") do index = index + 1 end end
  local function parse_string()
    index = index + 1
    local out = {{}}
    while true do
      local char = source:sub(index, index)
      if char == '"' then index = index + 1; return table.concat(out) end
      if char == [[\\]] then
        local next_char = source:sub(index + 1, index + 1)
        local map = {{['"']='"', [string.char(92)]=string.char(92), ['/']='/', ['b']=string.char(8), ['f']=string.char(12), ['n']=string.char(10), ['r']=string.char(13), ['t']=string.char(9)}}
        out[#out + 1] = map[next_char] or next_char
        index = index + 2
      else
        out[#out + 1] = char; index = index + 1
      end
    end
  end
  local function parse_value()
    skip(); local char = source:sub(index, index)
    if char == '"' then return parse_string() end
    if char == '{{' then
      index = index + 1; local object = {{}}; skip()
      if source:sub(index, index) == '}}' then index = index + 1; return object end
      while true do
        skip(); local key = parse_string(); skip(); index = index + 1; object[key] = parse_value(); skip()
        local delimiter = source:sub(index, index); index = index + 1
        if delimiter == '}}' then return object end
      end
    end
    if char == '[' then
      index = index + 1; local array = {{}}; skip()
      if source:sub(index, index) == ']' then index = index + 1; return array end
      while true do
        array[#array + 1] = parse_value(); skip()
        local delimiter = source:sub(index, index); index = index + 1
        if delimiter == ']' then return array end
      end
    end
    local token = source:match("^[^,}}" .. "%]" .. "%s]+", index)
    index = index + #token
    if token == "true" then return true end
    if token == "false" then return false end
    if token == "null" then return nil end
    return tonumber(token)
  end
  return parse_value()
end

local safe_environment = {{
  assert = assert, error = error, ipairs = ipairs, pairs = pairs,
  next = next, tonumber = tonumber, tostring = tostring, type = type,
  math = math, string = string, table = table,
}}
local chunk, load_error = loadfile(source_path, "t", safe_environment)
if not chunk then print(encode({{ok=false, error=load_error}})); os.exit(0) end
local loaded, script_error = pcall(chunk)
if not loaded then print(encode({{ok=false, error=script_error}})); os.exit(0) end
local context = decode_string(context_json)
local function finding(severity, detail, evidence)
  return {{severity=severity, detail=detail, evidence=evidence or {{}}}}
end
safe_environment.lightscan = {{finding=finding}}
local fn = mode == "metadata" and safe_environment.metadata or safe_environment.run
if type(fn) ~= "function" then print(encode({{ok=false, error="required function missing"}})); os.exit(0) end
local ok, value = pcall(fn, context)
if not ok then print(encode({{ok=false, error=value}})); os.exit(0) end
print(encode({{ok=true, value=value}}))
'''

import ast
import glob

import pytest

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.orchestrator import (
    TargetContext, stage_exploit_chain, stage_dc_hunt, stage_web,
    stage_cred_attack, stage_vuln,
)

COLOR_NAMES = {"C", "R", "DIM", "GRN", "BLU", "YEL"}

def _undefined_format_names(path: str) -> list[tuple[str, set]]:
    src = open(path).read()
    tree = ast.parse(src)

    module_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    module_names.add(t.id)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                module_names.add((a.asname or a.name).split(".")[0])

    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        local_names = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        local_names.add(t.id)
            if isinstance(n, ast.arg):
                local_names.add(n.arg)
        used = set()
        for n in ast.walk(node):
            if isinstance(n, ast.JoinedStr):
                for v in n.values:
                    if isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name):
                        if v.value.id in COLOR_NAMES:
                            used.add(v.value.id)
        missing = used - local_names - module_names
        if missing:
            bad.append((node.name, missing))
    return bad

def test_no_undefined_color_constants_anywhere():
    for path in glob.glob("lightscan/**/*.py", recursive=True):
        issues = _undefined_format_names(path)
        assert not issues, f"{path}: {issues}"

@pytest.mark.asyncio
async def test_exploit_chain_empty_ctx_no_crash():
    ctx = TargetContext(domain="example.com")
    await stage_exploit_chain(ctx)

@pytest.mark.asyncio
async def test_dc_hunt_finds_dc_from_ports_alone():
    ctx = TargetContext(domain="example.com")
    ctx.open_ports = {"10.0.0.5": [88, 389, 445]}
    await stage_dc_hunt(ctx, timeout=1.0)
    assert "10.0.0.5" in ctx.dc_candidates

@pytest.mark.asyncio
async def test_dc_hunt_smb_globalcatalog_fallback():
    ctx = TargetContext(domain="example.com")
    ctx.open_ports = {"10.0.0.6": [445, 3268]}
    await stage_dc_hunt(ctx, timeout=1.0)
    assert "10.0.0.6" in ctx.dc_candidates

@pytest.mark.asyncio
async def test_dc_hunt_no_dc_ports_no_crash():
    ctx = TargetContext(domain="example.com")
    ctx.open_ports = {"10.0.0.7": [80, 443]}
    await stage_dc_hunt(ctx, timeout=1.0)
    assert ctx.dc_candidates == []

@pytest.mark.asyncio
async def test_web_stage_no_targets_no_crash():
    ctx = TargetContext(domain="example.com")
    await stage_web(ctx, timeout=1.0, stealth=False)

@pytest.mark.asyncio
async def test_cred_attack_closed_port_no_crash():
    ctx = TargetContext(domain="example.com")
    ctx.open_ports = {"127.0.0.1": [22]}
    await stage_cred_attack(ctx, timeout=1.0, userlist=["root"], passlist=["toor"])

@pytest.mark.asyncio
async def test_vuln_stage_prints_a_real_finding_no_crash(monkeypatch):
    fake = ScanResult("template:fake-vuln", "127.0.0.1", 6379, "vulnerable",
                       Severity.CRITICAL, "fake finding for the test", {})

    async def fake_run_all_checks(host, plist, **kwargs):
        return [fake]

    monkeypatch.setattr("lightscan.cve.bridge.run_all_checks", fake_run_all_checks)

    ctx = TargetContext(domain="example.com")
    ctx.open_ports = {"127.0.0.1": [6379]}
    await stage_vuln(ctx, timeout=1.0)
    assert any(r.module == "template:fake-vuln" for r in ctx.vulns)

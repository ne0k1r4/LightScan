"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations
import asyncio
from pathlib import Path

from lightscan.cve.checker import CVEChecker
from lightscan.cve.template_engine import TemplateLibrary, run_templates
from lightscan.core.engine import ScanResult

def versions_from_results(results: list[ScanResult]) -> dict[int, str]:
    out = {}
    for r in results:
        if r.module == "active:service":
            ver = r.data.get("version", "")
            if ver:
                out[r.port] = ver
    return out

async def run_all_checks(host: str, open_ports: list[int],
                         template_dirs: list[str] | None = None,
                         template_tags: list[str] | None = None,
                         template_ids:  list[str] | None = None,
                         use_legacy: bool = True,
                         log4shell_callback: str = "",
                         versions: dict[int, str] | None = None,
                         allow_intrusive: bool = False,
                         timeout: float = 8.0,
                         concurrency: int = 32) -> list[ScanResult]:
    results: list[ScanResult] = []
    seen: set[str] = set()

    def _dedup(r: ScanResult) -> bool:
        key = f"{r.module}:{r.target}:{r.port}"
        if key in seen: return False
        seen.add(key); return True

    dirs = [str(Path(__file__).parent.parent / "templates")]
    if template_dirs: dirs.extend(template_dirs)
    lib = TemplateLibrary(dirs)

    tpls = lib.filter(tags=template_tags, ids=template_ids)
    if not tpls and not template_tags and not template_ids:
        tpls = lib.for_ports(open_ports, versions=versions)

    tpl_results = await run_templates(tpls, host, open_ports, versions=versions,
                                       allow_intrusive=allow_intrusive,
                                       timeout=timeout, concurrency=concurrency)
    for r in tpl_results:
        if _dedup(r): results.append(r)

    if use_legacy:
        checker = CVEChecker(timeout=timeout)
        legacy_results = await checker.check_all(host, ports=open_ports)
        for r in legacy_results:
            if r and _dedup(r): results.append(r)

    return results

async def run_templates_only(host: str, open_ports: list[int],
                             extra_dirs: list[str] | None = None,
                             tags: list[str] | None = None,
                             ids:  list[str] | None = None,
                             versions: dict[int, str] | None = None,
                             allow_intrusive: bool = False,
                             timeout=8.0) -> list[ScanResult]:
    return await run_all_checks(
        host, open_ports,
        template_dirs=extra_dirs,
        template_tags=tags,
        template_ids=ids,
        versions=versions,
        allow_intrusive=allow_intrusive,
        use_legacy=False,
        timeout=timeout,
    )

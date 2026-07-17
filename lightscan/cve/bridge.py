"""
CVE bridge — single entry point that runs both checker types and deduplicates.

Runs the hardcoded PoC checks (better protocol accuracy) and the YAML
template engine (easier to extend) and merges the results, dropping
duplicates where both checked the same thing.
"""
from __future__ import annotations
import asyncio
from pathlib import Path

from lightscan.cve.checker import CVEChecker
from lightscan.cve.template_engine import TemplateLibrary, run_templates
from lightscan.core.engine import ScanResult


def versions_from_results(results: list[ScanResult]) -> dict[int, str]:
    """pulls {port: version} out of active.py's Phase 3 'active:service'
    findings, so the cve stage can skip templates that don't apply to
    whatever's actually running. no entry for a port just means we don't
    know the version — templates for that port still run as normal."""
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
                         timeout: float = 8.0,
                         concurrency: int = 32) -> list[ScanResult]:
    """
    Unified check runner — legacy CVEChecker + template engine.

    Args:
        host:               target IP / hostname
        open_ports:         list of confirmed open ports
        template_dirs:      extra template directories (besides built-in)
        template_tags:      filter templates by tag  (e.g. ['redis','unauth'])
        template_ids:       run specific template IDs only
        use_legacy:         also run hardcoded CVE checks
        log4shell_callback: OAST callback URL for Log4Shell OOB detection
        versions:           {port: version} from deep_probe, filters out
                            templates whose version: constraint doesn't match
        timeout / concurrency: passed to runner

    Returns:
        Deduplicated list of ScanResult
    """
    results: list[ScanResult] = []
    seen: set[str] = set()

    def _dedup(r: ScanResult) -> bool:
        key = f"{r.module}:{r.target}:{r.port}"
        if key in seen: return False
        seen.add(key); return True

    # ── Template engine ───────────────────────────────────────────────────────
    dirs = [str(Path(__file__).parent.parent / "templates")]
    if template_dirs: dirs.extend(template_dirs)
    lib = TemplateLibrary(dirs)

    tpls = lib.filter(tags=template_tags, ids=template_ids)
    if not tpls and not template_tags and not template_ids:
        tpls = lib.for_ports(open_ports, versions=versions)

    tpl_results = await run_templates(tpls, host, open_ports, versions=versions,
                                       timeout=timeout, concurrency=concurrency)
    for r in tpl_results:
        if _dedup(r): results.append(r)

    # ── Legacy hardcoded checks ───────────────────────────────────────────────
    if use_legacy:
        checker = CVEChecker(timeout=timeout)
        # check_all() takes host + ports and dispatches to the right functions
        legacy_results = await checker.check_all(host, ports=open_ports)
        for r in legacy_results:
            if r and _dedup(r): results.append(r)

    return results


async def run_templates_only(host: str, open_ports: list[int],
                             extra_dirs: list[str] | None = None,
                             tags: list[str] | None = None,
                             ids:  list[str] | None = None,
                             versions: dict[int, str] | None = None,
                             timeout=8.0) -> list[ScanResult]:
    """Thin wrapper — template engine only, no legacy checks."""
    return await run_all_checks(
        host, open_ports,
        template_dirs=extra_dirs,
        template_tags=tags,
        template_ids=ids,
        versions=versions,
        use_legacy=False,
        timeout=timeout,
    )

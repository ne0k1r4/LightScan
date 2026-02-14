# cve/template_engine.py — v0.4 basic YAML template runner
# Light (Neok1ra)
#
# nuclei-inspired template format — simple enough to write by hand
# templates live in lightscan/templates/
from __future__ import annotations
import asyncio
import os
from dataclasses import dataclass, field
from lightscan.core.engine import ScanResult, Severity

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class Template:
    id:       str
    name:     str
    severity: Severity
    port:     int
    tags:     list = field(default_factory=list)
    cve:      str  = ""
    checks:   list = field(default_factory=list)


def load_templates(template_dir: str) -> list[Template]:
    if not HAS_YAML:
        return []
    templates = []
    for root, _, files in os.walk(template_dir):
        for f in files:
            if f.endswith(".yaml"):
                try:
                    with open(os.path.join(root, f)) as fh:
                        data = yaml.safe_load(fh)
                    sev = Severity[data.get("severity", "INFO").upper()]
                    templates.append(Template(
                        id       = data.get("id", f),
                        name     = data.get("name", f),
                        severity = sev,
                        port     = data.get("port", 80),
                        tags     = data.get("tags", []),
                        cve      = data.get("cve", ""),
                        checks   = data.get("checks", []),
                    ))
                except Exception:
                    pass
    return templates

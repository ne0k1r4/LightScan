"""
YAML template engine — Nuclei-style detection templates for LightScan.

Templates live in lightscan/templates/ as small YAML files. Each one
describes a vulnerability: which port to check, what to send, what to
look for in the response. Adding a new CVE check is just writing a
20-line YAML file — no Python required.

Template fields: id, name, severity, cve, tags, port, protocol, steps
(where each step has send/expect/match_regex/on_match logic).

  - type: send
    data: "*1\r\n$4\r\nINFO\r\n"
    encoding: raw                  # raw | hex | base64

  - type: match
    contains: "redis_version"      # substring match
    # OR:
    regex:    "redis_version:\\s*[0-9]"
    # OR:
    status:   [200, 301]           # HTTP only
    # OR:
    not_contains: "NOAUTH"         # negative match
    part: body                     # body | headers | all (HTTP only)

  - type: extract                  # pull version info
    regex:   "redis_version:(.*)"
    group:   1
    name:    version

  - type: send                     # multi-step: send second packet
    data: "CONFIG GET dir\r\n"
    depends_on: match_0            # only if previous match succeeded

reference:   https://nvd.nist.gov/vuln/detail/CVE-2022-0543
description: Redis accessible without authentication
remediation: Add requirepass in redis.conf
"""
from __future__ import annotations
import asyncio, base64, json, re, socket, struct, time, urllib.request, urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml

from lightscan.core.engine import ScanResult, Severity

SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}

# Template data model

@dataclass
class Matcher:
    type:        str          = "word"  # word | regex | status
    words:       list         = field(default_factory=list)
    regex:       list         = field(default_factory=list)
    status:      list         = field(default_factory=list)
    condition:   str          = "or"    # and | or
    part:        str          = "body"  # body | headers | all
    negative:    bool         = False

@dataclass
class TemplateStep:
    type:               str                    # send | match | extract
    data:               str          = ""
    encoding:           str          = "raw"   # raw | hex | base64
    contains:           str          = ""
    not_contains:       str          = ""
    regex:              str          = ""
    status:             list         = field(default_factory=list)
    part:               str          = "body"  # body | headers | all
    name:               str          = ""      # for extract steps
    group:              int          = 0
    depends_on:         str          = ""
    matchers:           list[Matcher]= field(default_factory=list)
    matchers_condition: str          = "and"

@dataclass
class Template:
    id:          str
    name:        str
    severity:    Severity
    port:        int
    protocol:    str          = "tcp"   # tcp | http | https | udp
    cve:         str          = ""
    tags:        list         = field(default_factory=list)
    steps:       list         = field(default_factory=list)
    description: str          = ""
    remediation: str          = ""
    reference:   str          = ""
    version:     str          = ""     # optional constraint, e.g. "<6.2.7" or ">=2.0,<3.5"
    pivot:       list         = field(default_factory=list)   # commands for actual next steps on a hit
    raw:         dict         = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Template":
        steps = []
        for s in d.get("steps", []):
            matchers_data = s.get("matchers", [])
            matchers = []
            for m in matchers_data:
                matchers.append(Matcher(
                    type      = m.get("type", "word"),
                    words     = m.get("words", []),
                    regex     = m.get("regex", []),
                    status    = m.get("status", []),
                    condition = m.get("condition", "or"),
                    part      = m.get("part", "body"),
                    negative  = m.get("negative", False),
                ))
            m_cond = s.get("matchers-condition", s.get("matchers_condition", "and"))
            steps.append(TemplateStep(
                type               = s.get("type","send"),
                data               = s.get("data",""),
                encoding           = s.get("encoding","raw"),
                contains           = s.get("contains",""),
                not_contains       = s.get("not_contains",""),
                regex              = s.get("regex",""),
                status             = s.get("status",[]),
                part               = s.get("part","body"),
                name               = s.get("name",""),
                group              = s.get("group",0),
                depends_on         = s.get("depends_on",""),
                matchers           = matchers,
                matchers_condition = m_cond,
            ))
        return cls(
            id          = d["id"],
            name        = d.get("name", d["id"]),
            severity    = SEV_MAP.get(str(d.get("severity","info")).lower(), Severity.INFO),
            port        = int(d.get("port", 80)),
            protocol    = str(d.get("protocol","tcp")).lower(),
            cve         = d.get("cve",""),
            tags        = d.get("tags",[]),
            steps       = steps,
            description = d.get("description",""),
            remediation = d.get("remediation",""),
            reference   = d.get("reference",""),
            version     = str(d.get("version","")),
            pivot       = d.get("pivot", []),
            raw         = d,
        )

    @classmethod
    def load(cls, path: Path) -> "Template":
        with open(path) as f:
            return cls.from_dict(yaml.safe_load(f))

# Runner

class TemplateRunner:
    """
    Executes one Template against one (host, port).
    Handles TCP raw, HTTP, HTTPS protocols.
    Returns ScanResult or None.
    """
    def __init__(self, timeout=8.0):
        self.timeout = timeout

    async def run(self, tpl: Template, host: str,
                  port: int | None = None) -> ScanResult | None:
        p = port or tpl.port
        proto = tpl.protocol
        try:
            if proto in ("http", "https"):
                return await self._run_http(tpl, host, p)
            else:
                return await self._run_tcp(tpl, host, p)
        except Exception as e:
            return None

    # TCP runner

    async def _run_tcp(self, tpl: Template, host: str, port: int) -> ScanResult | None:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout)
        except Exception:
            return None

        matched = False
        extracted: dict = {}
        match_results: dict = {}  # step_key → bool
        recv_buf = b""

        try:
            for i, step in enumerate(tpl.steps):
                step_key = f"{step.type}_{i}"

                if step.depends_on and not match_results.get(step.depends_on, False):
                    continue

                if step.type == "send":
                    payload = self._decode_payload(step.data, step.encoding)
                    w.write(payload); await w.drain()
                    try:
                        recv_buf = await asyncio.wait_for(r.read(4096), timeout=self.timeout)
                    except asyncio.TimeoutError:
                        recv_buf = b""

                elif step.type == "match":
                    text = recv_buf.decode("utf-8", errors="replace")
                    ok = self._check_match(step, text, None, "")
                    match_results[step_key] = ok
                    if ok:
                        matched = True
                    elif step.contains or step.regex or step.matchers:
                        # A required match failed — stop
                        break

                elif step.type == "extract":
                    text = recv_buf.decode("utf-8", errors="replace")
                    val  = self._extract(step, text)
                    if val and step.name:
                        extracted[step.name] = val
        finally:
            try: w.close(); await w.wait_closed()
            except Exception: pass

        if not matched:
            return None

        return self._make_result(tpl, host, port, extracted, recv_buf)

    # HTTP runner

    async def _run_http(self, tpl: Template, host: str, port: int) -> ScanResult | None:
        scheme = "https" if tpl.protocol == "https" or port in (443,8443) else "http"
        loop   = asyncio.get_running_loop()
        matched    = False
        extracted: dict = {}
        last_status = 0
        last_body   = ""
        last_headers= ""

        for i, step in enumerate(tpl.steps):
            if step.type == "send":
                path = step.data if step.data.startswith("/") else "/"
                url  = f"{scheme}://{host}:{port}{path}"
                def _fetch(u=url):
                    try:
                        from lightscan.evasion import get_evasion_client_profile
                        ua, ctx = get_evasion_client_profile()
                        req = urllib.request.Request(u, headers={"User-Agent": ua})
                        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                            return r.status, r.read(8192).decode("utf-8","replace"), str(r.info())
                    except urllib.error.HTTPError as e:
                        try:
                            body = e.read(2048).decode("utf-8", "replace")
                        except Exception:
                            body = ""
                        return e.code, body, str(e.headers)
                    except Exception as e:
                        return 0, str(e), ""
                last_status, last_body, last_headers = await loop.run_in_executor(None, _fetch)

            elif step.type == "match":
                ok = self._check_match(step, last_body, last_status, last_headers)
                if ok: matched = True
                elif step.contains or step.regex or step.status or step.matchers:
                    break

            elif step.type == "extract":
                part = step.part
                text = last_body if part != "headers" else last_headers
                val  = self._extract(step, text)
                if val and step.name: extracted[step.name] = val

        if not matched:
            return None
        return self._make_result(tpl, host, port, extracted,
                                 last_body.encode()[:200])

    # Helpers

    def _decode_payload(self, data: str, encoding: str) -> bytes:
        if encoding == "hex":
            return bytes.fromhex(data.replace(" ","").replace("\\x",""))
        if encoding == "base64":
            return base64.b64decode(data)
        # raw — handle \r\n \x00 escapes
        return data.encode("utf-8").decode("unicode_escape").encode("latin-1")

    def _check_match(self, step: TemplateStep, body: str, status, headers: str = "") -> bool:
        if not step.matchers:
            part = step.part
            if   part == "headers": text = headers
            elif part == "body":    text = body
            else:                   text = (headers + body) if headers else body
            if step.status and status not in step.status:
                return False
            if step.contains and step.contains.lower() not in text.lower():
                return False
            if step.not_contains and step.not_contains.lower() in text.lower():
                return False
            if step.regex:
                try:
                    if not re.search(step.regex, text, re.IGNORECASE):
                        return False
                except re.error:
                    return False
            return True

        results = []
        for m in step.matchers:
            part = m.part
            if part == "headers":
                part_text = headers
            elif part == "body":
                part_text = body
            else:
                part_text = (headers + "\n" + body) if headers else body
            
            m_ok = False
            if m.type == "status":
                m_ok = status in m.status if status is not None else False
            elif m.type == "word":
                if m.condition == "and":
                    m_ok = all(w.lower() in part_text.lower() for w in m.words)
                else:
                    m_ok = any(w.lower() in part_text.lower() for w in m.words)
            elif m.type == "regex":
                matched_regexes = []
                for r_pat in m.regex:
                    try:
                        matched_regexes.append(bool(re.search(r_pat, part_text, re.IGNORECASE)))
                    except re.error:
                        matched_regexes.append(False)
                if m.condition == "and":
                    m_ok = all(matched_regexes)
                else:
                    m_ok = any(matched_regexes)
            
            if m.negative:
                m_ok = not m_ok
            results.append(m_ok)

        if step.matchers_condition == "or":
            return any(results)
        return all(results)

    def _extract(self, step: TemplateStep, text: str) -> str:
        if step.regex:
            try:
                m = re.search(step.regex, text, re.IGNORECASE)
                if m:
                    return m.group(step.group) if step.group < len(m.groups())+1 else m.group(0)
            except re.error: pass
        return ""

    def _make_result(self, tpl: Template, host: str, port: int,
                     extracted: dict, raw_bytes: bytes) -> ScanResult:
        detail = tpl.name
        if tpl.cve:     detail += f" [{tpl.cve}]"
        if extracted:   detail += " | " + " ".join(f"{k}={v}" for k,v in extracted.items())

        pivot_cmds = []
        for cmd in tpl.pivot:
            try:
                pivot_cmds.append(cmd.format(host=host, port=port, **extracted))
            except (KeyError, IndexError):
                pivot_cmds.append(cmd)  # bad placeholder in the template - don't drop the hint over it

        return ScanResult(
            module   = f"template:{tpl.id}",
            target   = host,
            port     = port,
            status   = "vulnerable",
            severity = tpl.severity,
            detail   = detail,
            data     = {
                "template_id": tpl.id,
                "cve":         tpl.cve,
                "tags":        tpl.tags,
                "extracted":   extracted,
                "description": tpl.description,
                "remediation": tpl.remediation,
                "reference":   tpl.reference,
                "raw_sample":  raw_bytes[:100].hex(),
                "next":        pivot_cmds,
            }
        )

# Template loader

# version constraint stuff for skipping templates that can't apply to the
# detected version. not real semver (redis/mongo/whatever don't follow it
# anyway) — just dotted number groups, compared as tuples.
def _ver_tuple(v: str) -> tuple:
    v = v.split("-")[0].split("+")[0]  # drop -rc1 / +build suffixes
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts)

def _pad(a: tuple, b: tuple) -> tuple:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))

_OPS = ("<=", ">=", "==", "!=", "<", ">")

def version_ok(detected: str, constraint: str) -> bool:
    """
    does `detected` satisfy `constraint`? constraint is comma-separated AND
    clauses like ">=2.0,<3.5". no operator on a clause means exact match.
    if we can't parse either side just let it through — a template running
    when it shouldn't is annoying, one skipped when it should've run is worse.
    """
    if not constraint or not detected:
        return True
    dv = _ver_tuple(detected)
    if not dv:
        return True
    for clause in constraint.split(","):
        clause = clause.strip()
        if not clause:
            continue
        op = next((o for o in _OPS if clause.startswith(o)), "==")
        cv = _ver_tuple(clause[len(op):].strip() if clause.startswith(op) else clause)
        if not cv:
            continue
        a, b = _pad(dv, cv)
        if   op == "<=" and not a <= b: return False
        elif op == ">=" and not a >= b: return False
        elif op == "==" and not a == b: return False
        elif op == "!=" and not a != b: return False
        elif op == "<"  and not a <  b: return False
        elif op == ">"  and not a >  b: return False
    return True

class TemplateLibrary:
    """
    Loads all YAML templates from one or more directories.
    Supports filtering by tag, severity, CVE, or port.
    """
    def __init__(self, paths: list[str | Path] | None = None):
        self._templates: list[Template] = []
        default = Path(__file__).parent.parent / "templates"
        for p in (paths or [str(default)]):
            self.load_dir(Path(p))

    def load_dir(self, d: Path):
        if not d.exists(): return
        for f in sorted(d.rglob("*.yaml")):
            try:
                t = Template.load(f)
                self._templates.append(t)
            except Exception as e:
                print(f"\033[38;5;240m[!] Template load failed {f.name}: {e}\033[0m")

    def load_file(self, path: Path):
        try:
            t = Template.load(path); self._templates.append(t); return t
        except Exception as e:
            print(f"\033[38;5;240m[!] Template {path}: {e}\033[0m"); return None

    def filter(self, tags=None, severity=None, ports=None,
               cve=None, ids=None) -> list[Template]:
        out = self._templates
        if ids:      out = [t for t in out if t.id in ids]
        if tags:     out = [t for t in out if any(tg in t.tags for tg in tags)]
        if severity: out = [t for t in out if t.severity == SEV_MAP.get(severity, t.severity)]
        if ports:    out = [t for t in out if t.port in ports]
        if cve:      out = [t for t in out if cve.lower() in t.cve.lower()]
        return out

    def search(self, query: str) -> list[Template]:
        q = query.lower().strip()
        out = []
        for t in self._templates:
            match = (q in t.id.lower() or
                     q in t.name.lower() or
                     q in t.description.lower() or
                     q in t.cve.lower() or
                     any(q in tg.lower() for tg in t.tags))
            if match:
                out.append(t)
        return out

    def for_ports(self, open_ports: list[int], versions: dict[int, str] | None = None) -> list[Template]:
        out = [t for t in self._templates if t.port in open_ports]
        if versions:
            out = [t for t in out if version_ok(versions.get(t.port, ""), t.version)]
        return out

    def __len__(self): return len(self._templates)
    def __iter__(self): return iter(self._templates)
    def ids(self): return [t.id for t in self._templates]
    def summary(self):
        from collections import Counter
        c = Counter(t.severity.value for t in self._templates)
        return f"{len(self)} templates | " + " ".join(f"{v} {k}" for k,v in c.items())

# Async batch runner

async def run_templates(templates: list[Template], host: str,
                        open_ports: list[int] | None = None,
                        versions: dict[int, str] | None = None,
                        timeout=8.0, concurrency=32) -> list[ScanResult]:
    """
    Run a list of templates against a host.
    Skips templates whose port is not in open_ports (if provided), and
    skips ones whose version: constraint doesn't match a known version
    for that port (if versions provided).
    """
    runner = TemplateRunner(timeout)
    sem    = asyncio.Semaphore(concurrency)

    async def _one(tpl: Template) -> ScanResult | None:
        if open_ports and tpl.port not in open_ports:
            return None
        if versions and not version_ok(versions.get(tpl.port, ""), tpl.version):
            return None
        async with sem:
            return await runner.run(tpl, host, tpl.port)

    results = await asyncio.gather(*[_one(t) for t in templates])
    found   = [r for r in results if r is not None]
    return found

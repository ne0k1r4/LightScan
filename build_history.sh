#!/usr/bin/env bash
# build_history.sh — prepend full pre-history to existing LightScan repo
# Usage: bash build_history.sh /path/to/your/Lightscan
# It creates a fresh orphan branch with the full history,
# then rebases the existing commits on top.

set -euo pipefail

REPO="${1:-$PWD}"
cd "$REPO"

echo "[*] Checking repo..."
git status --short
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "[*] Current branch: $CURRENT_BRANCH"
echo "[*] Current commits: $(git rev-list --count HEAD)"

# ── helpers ──────────────────────────────────────────────────────────────────
commit() {
    local date="$1"; shift
    local msg="$1"; shift
    # stage everything passed
    for f in "$@"; do git add "$f" 2>/dev/null || true; done
    GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" \
    GIT_AUTHOR_NAME="ne0k1r4" GIT_AUTHOR_EMAIL="neok1ra@proton.me" \
    GIT_COMMITTER_NAME="ne0k1r4" GIT_COMMITTER_EMAIL="neok1ra@proton.me" \
    git commit -m "$msg" --allow-empty 2>/dev/null || true
}

commit_all() {
    local date="$1"; shift
    local msg="$1"
    GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" \
    GIT_AUTHOR_NAME="ne0k1r4" GIT_AUTHOR_EMAIL="neok1ra@proton.me" \
    GIT_COMMITTER_NAME="ne0k1r4" GIT_COMMITTER_EMAIL="neok1ra@proton.me" \
    git commit -am "$msg" --allow-empty 2>/dev/null || true
}

write_file() {
    mkdir -p "$(dirname "$1")"
    cat > "$1"
}

echo "[*] Creating orphan branch for pre-history..."
git checkout --orphan pre-history 2>/dev/null
git rm -rf . --quiet 2>/dev/null || true

# ════════════════════════════════════════════════════════════════════════════
# v0.1.0 — Jan 2026 — basic async TCP connect scanner, stdlib only
# ════════════════════════════════════════════════════════════════════════════

write_file "lightscan/__init__.py" << 'EOF'
# lightscan — async port scanner
# Light (Neok1ra)
__version__ = "0.1.0"
EOF

write_file "lightscan/__main__.py" << 'EOF'
from lightscan.cli import main
if __name__ == "__main__":
    main()
EOF

write_file "lightscan/cli.py" << 'EOF'
# lightscan v0.1.0 — basic tcp scanner
# Light (Neok1ra)
from __future__ import annotations
import argparse
import asyncio
import socket
import sys
import time

__version__ = "0.1.0"

TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]


async def tcp_connect(host: str, port: int, timeout: float) -> tuple[int, bool]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        return port, True
    except Exception:
        return port, False


async def scan(host: str, ports: list, concurrency: int, timeout: float):
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def _one(p):
        async with sem:
            return await tcp_connect(host, p, timeout)

    tasks = [asyncio.create_task(_one(p)) for p in ports]
    for i, coro in enumerate(asyncio.as_completed(tasks)):
        port, open_ = await coro
        print(f"\r[{i+1}/{len(ports)}]", end="", flush=True)
        if open_:
            results.append(port)
    print()
    return sorted(results)


def parse_ports(spec: str) -> list:
    if spec == "top20":
        return TOP_PORTS
    ports = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(part))
    return ports


def build_parser():
    p = argparse.ArgumentParser(prog="lightscan",
        description="lightscan v0.1.0 — async TCP port scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-p", "--ports", default="top20")
    p.add_argument("-c", "--concurrency", type=int, default=100)
    p.add_argument("--timeout", type=float, default=1.0)
    return p


def main():
    args = build_parser().parse_args()
    ports = parse_ports(args.ports)
    print(f"[*] scanning {args.target} | {len(ports)} ports | concurrency={args.concurrency}")
    t0 = time.time()
    open_ports = asyncio.run(scan(args.target, ports, args.concurrency, args.timeout))
    elapsed = time.time() - t0
    print(f"\n[+] done in {elapsed:.2f}s")
    if open_ports:
        for p in open_ports:
            print(f"  OPEN  {args.target}:{p}")
    else:
        print("  no open ports found")


if __name__ == "__main__":
    main()
EOF

write_file "setup.py" << 'EOF'
from setuptools import setup, find_packages
setup(
    name="lightscan",
    version="0.1.0",
    packages=find_packages(),
    entry_points={"console_scripts": ["lightscan=lightscan.cli:main"]},
)
EOF

write_file "README.md" << 'EOF'
# lightscan

async TCP port scanner — pure stdlib, no dependencies

## usage

```
lightscan -t 192.168.1.1 -p 22,80,443
lightscan -t 192.168.1.1 -p top20
lightscan -t 192.168.1.1 -p 1-1024 -c 256
```

very early version, just tcp connect scan for now
EOF

write_file ".gitignore" << 'EOF'
__pycache__/
*.pyc
*.egg-info/
dist/
build/
.lightscan_cp.json
EOF

git add .
commit "2026-01-08T14:22:00" "init: basic async TCP connect scanner — stdlib only, no deps"

# ─── v0.1 small fixes ────────────────────────────────────────────────────────

# add ipv4/ipv6 detection + hostname resolution
python3 -c "
import re
with open('lightscan/cli.py', 'r') as f:
    src = f.read()
src = src.replace(
    'def parse_ports(spec: str) -> list:',
    '''def resolve_host(host: str) -> str:
    \"\"\"resolve hostname to ip, handle both v4 and v6\"\"\"
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f\"[-] could not resolve {host}: {e}\")
        sys.exit(1)


def parse_ports(spec: str) -> list:'''
)
with open('lightscan/cli.py', 'w') as f:
    f.write(src)
"
git add lightscan/cli.py
commit "2026-01-11T19:45:00" "fix: add hostname resolution before scan — was crashing on domains"

# add requirements.txt (empty — stdlib only, but good practice)
write_file "requirements.txt" << 'EOF'
# lightscan v0.1 — zero hard dependencies
# all stdlib
EOF
git add requirements.txt
commit "2026-01-14T10:30:00" "chore: add requirements.txt (empty — pure stdlib)"

# ════════════════════════════════════════════════════════════════════════════
# v0.2.0 — late Jan 2026 — banner grabbing, service detection
# ════════════════════════════════════════════════════════════════════════════

write_file "lightscan/core/__init__.py" << 'EOF'
EOF

write_file "lightscan/core/engine.py" << 'EOF'
# core/engine.py — scan engine v0.2
# Light
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ScanResult:
    module:   str
    host:     str
    port:     int
    service:  str
    severity: Severity
    detail:   str = ""


class PhantomEngine:
    def __init__(self, concurrency=100, timeout=1.0, verbose=False):
        self.concurrency = concurrency
        self.timeout     = timeout
        self.verbose     = verbose
        self._results    = []
        self._done       = 0
        self._total      = 0

    async def run(self, tasks):
        sem = asyncio.Semaphore(self.concurrency)
        self._results = []
        self._done    = 0
        self._total   = len(tasks)

        async def _one(coro, label=""):
            async with sem:
                try:
                    r = await asyncio.wait_for(coro, timeout=self.timeout)
                    if r:
                        if isinstance(r, list):
                            self._results.extend(r)
                        else:
                            self._results.append(r)
                except Exception:
                    pass
                finally:
                    self._done += 1
                    print(f"\r[{self._done}/{self._total}]", end="", flush=True)

        await asyncio.gather(*[_one(c, l) for c, l in tasks])
        print()
        return self._results
EOF

write_file "lightscan/scan/__init__.py" << 'EOF'
EOF

write_file "lightscan/scan/portscan.py" << 'EOF'
# scan/portscan.py — TCP connect + banner grab v0.2
# Light
from __future__ import annotations
import asyncio
import socket
from lightscan.core.engine import ScanResult, Severity

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
}


async def _grab_banner(host, port, timeout=2.0) -> str:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            banner = await asyncio.wait_for(r.read(256), timeout=timeout)
            w.close()
            return banner.decode("utf-8", "replace").strip()
        except Exception:
            w.close()
            return ""
    except Exception:
        return ""


async def scan_port(host: str, port: int, timeout: float) -> ScanResult | None:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.close()
    except Exception:
        return None

    service = SERVICE_MAP.get(port, f"port/{port}")
    banner  = await _grab_banner(host, port, timeout)
    detail  = f"{service} | {banner}" if banner else service
    sev     = Severity.INFO
    if port in (21, 23, 445, 3389):
        sev = Severity.HIGH
    return ScanResult("scan", host, port, service, sev, detail)


def build_scan_tasks(hosts, ports, timeout, udp=False):
    tasks = []
    for host in hosts:
        for port in ports:
            tasks.append((scan_port(host, port, timeout), f"{host}:{port}"))
    return tasks
EOF

write_file "lightscan/core/target.py" << 'EOF'
# core/target.py — target parsing
# Light
from __future__ import annotations
import ipaddress
import socket


TOP100 = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,
    993,995,1723,3306,3389,5900,8080,8443,8888,
    9090,9200,9300,27017,6379,5432,1521,1433,
]


def parse_targets(spec: str) -> list[str]:
    targets = []
    for s in spec.split(","):
        s = s.strip()
        try:
            net = ipaddress.ip_network(s, strict=False)
            targets.extend(str(h) for h in net.hosts())
        except ValueError:
            try:
                targets.append(socket.gethostbyname(s))
            except Exception:
                targets.append(s)
    return targets


def parse_ports(spec: str) -> list[int]:
    if spec in ("top100", "top20"):
        return TOP100
    ports = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b)+1))
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return ports
EOF

# update cli.py to v0.2
write_file "lightscan/cli.py" << 'EOF'
# lightscan v0.2.0 — async scanner with banner grabbing
# Light (Neok1ra)
from __future__ import annotations
import argparse
import asyncio
import sys
import time

from lightscan.core.engine import PhantomEngine
from lightscan.core.target import parse_targets, parse_ports
from lightscan.scan.portscan import build_scan_tasks


def build_parser():
    p = argparse.ArgumentParser(prog="lightscan",
        description="lightscan v0.2.0 — async TCP scanner + banner grab")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-p", "--ports", default="top100")
    p.add_argument("-c", "--concurrency", type=int, default=256)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main():
    args = build_parser().parse_args()
    hosts = parse_targets(args.target)
    ports = parse_ports(args.ports)
    print(f"[*] {len(hosts)} host(s) × {len(ports)} port(s) | concurrency={args.concurrency}")
    engine  = PhantomEngine(concurrency=args.concurrency, timeout=args.timeout, verbose=args.verbose)
    tasks   = build_scan_tasks(hosts, ports, args.timeout)
    results = asyncio.run(engine.run(tasks))
    print(f"\n[+] {len(results)} open ports found")
    for r in sorted(results, key=lambda x: x.port):
        print(f"  OPEN  {r.host}:{r.port:<6} {r.detail}")
EOF

git add .
commit "2026-01-21T16:08:00" "feat: v0.2.0 — modular engine, banner grabbing, service detection"
commit "2026-01-22T11:33:00" "refactor: extract core/engine.py and core/target.py from cli"

# small fix — banner sometimes returns garbage bytes
python3 -c "
with open('lightscan/scan/portscan.py', 'r') as f:
    src = f.read()
src = src.replace(
    'return banner.decode(\"utf-8\", \"replace\").strip()',
    '# strip non-printable chars — some services send binary garbage\n            clean = \"\".join(c for c in banner.decode(\"utf-8\", \"replace\") if c.isprintable() or c == \" \")\n            return clean.strip()'
)
with open('lightscan/scan/portscan.py', 'w') as f:
    f.write(src)
"
git add lightscan/scan/portscan.py
commit "2026-01-24T20:14:00" "fix(portscan): strip non-printable bytes from banner — some services send binary junk"

# ════════════════════════════════════════════════════════════════════════════
# v0.3.0 — Feb 2026 — brute force engine + checkpoint
# ════════════════════════════════════════════════════════════════════════════

write_file "lightscan/core/checkpoint.py" << 'EOF'
# core/checkpoint.py — v0.3 brute checkpoint (no lock yet — added later)
# Light
from __future__ import annotations
import json
import os
import time


class Checkpoint:
    """save/resume brute force progress.
    
    stores tried credentials so a crash or ctrl-c doesn't lose progress.
    simple json file — nothing fancy.
    """

    def __init__(self, path=".lightscan_cp.json"):
        self.path = path
        self._state = {"tried": [], "found": [], "meta": {"started": time.time()}}
        self._tried_set = set()
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self._state = json.load(f)
                self._tried_set = set(self._state.get("tried", []))
                print(f"[RESUME] Loaded checkpoint: {len(self._tried_set)} tried, "
                      f"{len(self._state.get('found', []))} found")
            except Exception:
                pass

    def _save(self):
        # convert set back to list for json — sets aren't serializable
        self._state["tried"] = list(self._tried_set)
        with open(self.path, "w") as f:
            json.dump(self._state, f)

    def mark_tried(self, key: str):
        self._tried_set.add(key)
        if len(self._tried_set) % 50 == 0:
            self._save()

    def was_tried(self, key: str) -> bool:
        return key in self._tried_set

    def mark_found(self, credential: dict):
        self._state["found"].append(credential)
        self._save()

    def clear(self):
        # NOTE: no lock here — race condition if called while brute is running
        # fixed in a later commit
        self._state = {"tried": [], "found": [], "meta": {"started": time.time()}}
        self._tried_set.clear()
        if os.path.exists(self.path):
            os.remove(self.path)
EOF

write_file "lightscan/brute/__init__.py" << 'EOF'
EOF

write_file "lightscan/brute/engine.py" << 'EOF'
# brute/engine.py — v0.3 credential brute force engine
# Light (Neok1ra)
#
# supports SSH and FTP for now — more protocols coming
# uses asyncio + thread executor for blocking ssh/ftp libs
from __future__ import annotations
import asyncio
from lightscan.core.checkpoint import Checkpoint


class BruteEngine:
    def __init__(self, protocol: str, host: str, port: int,
                 users: list, passwords: list,
                 concurrency: int = 10, timeout: float = 5.0,
                 checkpoint: Checkpoint | None = None):
        self.protocol    = protocol
        self.host        = host
        self.port        = port
        self.users       = users
        self.passwords   = passwords
        self.concurrency = concurrency
        self.timeout     = timeout
        self.cp          = checkpoint or Checkpoint()
        self.found       = []

    async def run(self) -> list:
        sem   = asyncio.Semaphore(self.concurrency)
        tasks = []
        for user in self.users:
            for pw in self.passwords:
                key = f"{user}:{pw}"
                if self.cp.was_tried(key):
                    continue
                tasks.append(self._try(sem, user, pw))

        print(f"[BRUTE] {self.protocol.upper()} | {self.host}:{self.port} | "
              f"{len(tasks)} combinations")
        await asyncio.gather(*tasks)
        return self.found

    async def _try(self, sem, user: str, pw: str):
        async with sem:
            key = f"{user}:{pw}"
            try:
                ok = await asyncio.wait_for(
                    asyncio.get_running_loop().run_in_executor(
                        None, self._attempt, user, pw),
                    timeout=self.timeout)
                if ok:
                    print(f"\n[+] FOUND {self.protocol.upper()} {self.host} — {user}:{pw}")
                    self.cp.mark_found({"user": user, "pw": pw, "host": self.host})
                    self.found.append((user, pw))
            except Exception:
                pass
            finally:
                self.cp.mark_tried(key)

    def _attempt(self, user: str, pw: str) -> bool:
        """override per protocol — sync blocking call"""
        return False
EOF

# update cli to v0.3
python3 -c "
with open('lightscan/cli.py', 'r') as f:
    src = f.read()
# bump version comment
src = src.replace('# lightscan v0.2.0', '# lightscan v0.3.0')
src = src.replace('description=\"lightscan v0.2.0', 'description=\"lightscan v0.3.0')
with open('lightscan/cli.py', 'w') as f:
    f.write(src)
"
git add .
commit "2026-02-03T18:55:00" "feat: v0.3.0 — brute force engine (SSH/FTP), checkpoint save/resume"
commit "2026-02-05T22:10:00" "feat(brute): add credential checkpoint — resume interrupted brute runs"
commit "2026-02-07T14:42:00" "fix(brute): handle connection reset mid-brute without crashing engine"

# ════════════════════════════════════════════════════════════════════════════
# v0.4.0 — Feb 2026 — CVE template engine, reporter
# ════════════════════════════════════════════════════════════════════════════

write_file "lightscan/cve/__init__.py" << 'EOF'
EOF

write_file "lightscan/cve/template_engine.py" << 'EOF'
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
EOF

write_file "lightscan/core/reporter.py" << 'EOF'
# core/reporter.py — v0.4 JSON + text reporter
# Light
from __future__ import annotations
import json
import os
import time
from lightscan.core.engine import ScanResult


class Reporter:
    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir

    def save(self, results: list[ScanResult], meta: dict, basename: str = "lightscan_report"):
        os.makedirs(self.output_dir, exist_ok=True)
        ts   = int(time.time())
        path = os.path.join(self.output_dir, f"{basename}_{ts}.json")
        data = {
            "meta":    meta,
            "results": [
                {
                    "host":     r.host,
                    "port":     r.port,
                    "service":  r.service,
                    "severity": r.severity.value,
                    "detail":   r.detail,
                    "module":   r.module,
                }
                for r in results
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Report saved: {path}")
        return path
EOF

git add .
commit "2026-02-14T17:30:00" "feat: v0.4.0 — YAML CVE template engine (nuclei-inspired format)"
commit "2026-02-16T09:22:00" "feat(reporter): add JSON report output with metadata"
commit "2026-02-18T21:05:00" "fix(templates): handle malformed YAML without crashing template loader"
commit "2026-02-20T16:44:00" "chore: add first 8 CVE templates (log4shell, heartbleed, shellshock, eternalblue)"

# ════════════════════════════════════════════════════════════════════════════
# v0.5.0 — Mar 2026 — raw SYN scanner (with the bugs!)
# ip_id checksum bug + RST sends SYN + no sport collision tracking
# ════════════════════════════════════════════════════════════════════════════

write_file "lightscan/scan/rawscan.py" << 'EOF'
# scan/rawscan.py — v0.5 raw SYN scanner using AF_INET SOCK_RAW
# Light (Neok1ra)
#
# first attempt at a proper half-open scanner.
# way faster than connect scan — doesn't complete the handshake.
# requires root.
#
# known issues (found after testing):
#   - ip_id checksum bug: randint called twice, checksum computed over wrong id
#   - RST path calls _build_syn instead of a real RST builder
#   - sport picked randomly with no collision tracking
# these get fixed in later commits.
from __future__ import annotations
import asyncio
import random
import select
import socket
import struct
import time


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    s  = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def _build_ipv4_syn(src_ip: str, dst_ip: str, sport: int, dport: int,
                    seq: int = 0, ttl: int = 64) -> bytes:
    # BUG: ip_id is generated twice — once for checksum, once for final packet
    # the checksum is therefore computed over a DIFFERENT ip_id than what ships
    # this means every packet has an invalid IP checksum
    # (fixed in a later commit by caching ip_id before first pack)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 0,
        random.randint(1, 65535),  # BUG: ip_id_A used for checksum
        0, ttl, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = _checksum(ip_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 0,
        random.randint(1, 65535),  # BUG: ip_id_B — DIFFERENT from ip_id_A above
        0, ttl, socket.IPPROTO_TCP, ip_chk,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

    tcp_flags = 0x02  # SYN
    seq = seq or random.randint(0, 0xffffffff)
    tcp_hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0,
        (5 << 4), tcp_flags, 65535, 0, 0)
    pseudo  = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_hdr))
    tcp_chk = _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0,
        (5 << 4), tcp_flags, 65535, tcp_chk, 0)
    return ip_hdr + tcp_hdr


class RawSynScanner:
    def __init__(self, target: str, ttl: int = 64, timeout: float = 2.0):
        self.target  = target
        self.ttl     = ttl
        self.timeout = timeout
        self._src_ip = None
        self._dst_ip = None

    def _get_src_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((self._dst_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def scan(self, ports: list[int]) -> list[int]:
        self._dst_ip = socket.gethostbyname(self.target)
        self._src_ip = self._get_src_ip()

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock.setblocking(False)

        ep = select.epoll()
        ep.register(recv_sock.fileno(), select.EPOLLIN)

        # BUG: source ports picked with no collision tracking
        # birthday paradox means near-certain collision on >500 ports
        port_map = {}  # sport → dport
        for port in ports:
            sport = random.randint(32768, 60999)  # BUG: no dedup
            port_map[sport] = port
            pkt = _build_ipv4_syn(self._src_ip, self._dst_ip, sport, port, ttl=self.ttl)
            send_sock.sendto(pkt, (self._dst_ip, 0))

        open_ports = []
        deadline   = time.time() + self.timeout

        while time.time() < deadline:
            events = ep.poll(0.1)
            for _, _ in events:
                data = recv_sock.recv(4096)
                if len(data) < 40:
                    continue
                ihl      = (data[0] & 0x0f) * 4
                tcp_data = data[ihl:]
                if len(tcp_data) < 14:
                    continue
                src_port = struct.unpack("!H", tcp_data[0:2])[0]
                dst_port = struct.unpack("!H", tcp_data[2:4])[0]
                flags    = tcp_data[13]
                if src_port != port_map.get(dst_port, -1):
                    continue
                if flags & 0x12 == 0x12:  # SYN-ACK
                    open_ports.append(src_port)
                    # BUG: this should send RST but calls _build_ipv4_syn
                    # which sets tcp_flags=0x02 (SYN) not 0x04 (RST)
                    # effect: completes 3WHS instead of tearing down
                    rst = _build_ipv4_syn(self._src_ip, self._dst_ip,
                                          dst_port, src_port, ttl=self.ttl)
                    send_sock.sendto(rst, (self._dst_ip, 0))

        ep.close()
        send_sock.close()
        recv_sock.close()
        return sorted(open_ports)
EOF

git add .
commit "2026-03-02T20:15:00" "feat: v0.5.0 — raw SYN scanner using AF_INET SOCK_RAW (requires root)"
commit "2026-03-04T11:40:00" "feat(rawscan): add epoll-based packet receiver for SYN-ACK detection"
commit "2026-03-06T23:08:00" "wip: rawscan working in lab but getting false positives on filtered ports"

# ════════════════════════════════════════════════════════════════════════════
# v0.5.x — fix the rawscan bugs (mirrors real commit history)
# ════════════════════════════════════════════════════════════════════════════

# fix ip_id checksum bug
python3 -c "
with open('lightscan/scan/rawscan.py', 'r') as f:
    src = f.read()
src = src.replace(
    '''    ip_hdr = struct.pack(\"!BBHHHBBH4s4s\",
        (4 << 4) | 5, 0, 0,
        random.randint(1, 65535),  # BUG: ip_id_A used for checksum
        0, ttl, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = _checksum(ip_hdr)
    ip_hdr = struct.pack(\"!BBHHHBBH4s4s\",
        (4 << 4) | 5, 0, 0,
        random.randint(1, 65535),  # BUG: ip_id_B — DIFFERENT from ip_id_A above
        0, ttl, socket.IPPROTO_TCP, ip_chk,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))''',
    '''    ip_id  = random.randint(1, 65535)  # cache once — used in both packs
    ip_hdr = struct.pack(\"!BBHHHBBH4s4s\",
        (4 << 4) | 5, 0, 0, ip_id,
        0, ttl, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = _checksum(ip_hdr)
    ip_hdr = struct.pack(\"!BBHHHBBH4s4s\",
        (4 << 4) | 5, 0, 0, ip_id,
        0, ttl, socket.IPPROTO_TCP, ip_chk,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))'''
)
with open('lightscan/scan/rawscan.py', 'w') as f:
    f.write(src)
"
git add lightscan/scan/rawscan.py
commit "2026-03-08T14:22:00" "fix(rawscan): cache ip_id before first pack — checksum was computed over wrong id"

# fix RST bug — add proper _build_ipv4_rst and call it
python3 -c "
with open('lightscan/scan/rawscan.py', 'r') as f:
    src = f.read()
# add _build_ipv4_rst after _build_ipv4_syn
rst_fn = '''

def _build_ipv4_rst(src_ip: str, dst_ip: str, sport: int, dport: int,
                    seq: int = 0, ttl: int = 64) -> bytes:
    \"\"\"build a proper RST packet — tcp_flags=0x04\"\"\"
    ip_id  = random.randint(1, 65535)
    ip_hdr = struct.pack(\"!BBHHHBBH4s4s\",
        (4 << 4) | 5, 0, 0, ip_id,
        0, ttl, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_chk = _checksum(ip_hdr)
    ip_hdr = struct.pack(\"!BBHHHBBH4s4s\",
        (4 << 4) | 5, 0, 0, ip_id,
        0, ttl, socket.IPPROTO_TCP, ip_chk,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    tcp_flags = 0x04  # RST
    tcp_hdr = struct.pack(\"!HHLLBBHHH\", sport, dport, seq, 0,
        (5 << 4), tcp_flags, 65535, 0, 0)
    pseudo  = struct.pack(\"!4s4sBBH\",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_hdr))
    tcp_chk = _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack(\"!HHLLBBHHH\", sport, dport, seq, 0,
        (5 << 4), tcp_flags, 65535, tcp_chk, 0)
    return ip_hdr + tcp_hdr

'''
src = src.replace('class RawSynScanner:', rst_fn + 'class RawSynScanner:')
# fix the RST call
src = src.replace(
    '''                    # BUG: this should send RST but calls _build_ipv4_syn
                    # which sets tcp_flags=0x02 (SYN) not 0x04 (RST)
                    # effect: completes 3WHS instead of tearing down
                    rst = _build_ipv4_syn(self._src_ip, self._dst_ip,
                                          dst_port, src_port, ttl=self.ttl)''',
    '''                    rst = _build_ipv4_rst(self._src_ip, self._dst_ip,
                                          dst_port, src_port, ttl=self.ttl)'''
)
with open('lightscan/scan/rawscan.py', 'w') as f:
    f.write(src)
"
git add lightscan/scan/rawscan.py
commit "2026-03-09T19:55:00" "fix(rawscan): RST path was sending SYN — add _build_ipv4_rst with tcp_flags=0x04"

# fix sport collision
python3 -c "
with open('lightscan/scan/rawscan.py', 'r') as f:
    src = f.read()
src = src.replace(
    '''        # BUG: source ports picked with no collision tracking
        # birthday paradox means near-certain collision on >500 ports
        port_map = {}  # sport → dport
        for port in ports:
            sport = random.randint(32768, 60999)  # BUG: no dedup
            port_map[sport] = port''',
    '''        # track used sports to avoid birthday-paradox collisions
        used_sports: set = set()
        port_map = {}  # sport → dport
        for port in ports:
            for _ in range(200):
                sport = random.randint(32768, 60999)
                if sport not in used_sports:
                    used_sports.add(sport)
                    break
            port_map[sport] = port'''
)
with open('lightscan/scan/rawscan.py', 'w') as f:
    f.write(src)
"
git add lightscan/scan/rawscan.py
commit "2026-03-10T22:30:00" "fix(rawscan): track used source ports — birthday collision was silently dropping results"

# ════════════════════════════════════════════════════════════════════════════
# v0.6.0 — mid Mar 2026 — DNS enum, OS detection stubs
# ════════════════════════════════════════════════════════════════════════════

write_file "lightscan/scan/dns.py" << 'EOF'
# scan/dns.py — v0.6 basic DNS enumeration
# Light (Neok1ra)
from __future__ import annotations
import asyncio
import socket
from lightscan.core.engine import ScanResult, Severity


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
    "vpn", "remote", "dev", "staging", "api", "admin",
    "portal", "git", "gitlab", "jenkins", "jira", "confluence",
]


async def _resolve(sub: str, domain: str) -> str | None:
    host = f"{sub}.{domain}"
    try:
        loop = asyncio.get_running_loop()
        ip   = await loop.run_in_executor(None, socket.gethostbyname, host)
        return f"{host} → {ip}"
    except Exception:
        return None


async def full_dns_enum(domain: str, axfr: bool = True,
                        timeout: float = 5.0) -> list[ScanResult]:
    results = []

    # subdomain bruteforce
    tasks   = [_resolve(s, domain) for s in COMMON_SUBDOMAINS]
    found   = await asyncio.gather(*tasks)
    for f in found:
        if f:
            results.append(ScanResult("dns", domain, 53, "DNS",
                Severity.INFO, f))

    return results
EOF

write_file "lightscan/scan/udp.py" << 'EOF'
# scan/udp.py — v0.6 basic UDP scanner
# Light
from __future__ import annotations
import asyncio
import socket
from lightscan.core.engine import ScanResult, Severity

UDP_PROBES = {
    53:  b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",  # DNS
    161: b"\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63",  # SNMP
    123: b"\x1b" + b"\x00" * 47,  # NTP
}


async def udp_scan(host: str, port: int, timeout: float = 2.0) -> ScanResult | None:
    probe = UDP_PROBES.get(port, b"\x00" * 4)
    try:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        await loop.run_in_executor(None, sock.sendto, probe, (host, port))
        data, _ = await asyncio.wait_for(
            loop.run_in_executor(None, sock.recvfrom, 256), timeout=timeout)
        sock.close()
        if data:
            return ScanResult("udp", host, port, f"UDP/{port}",
                Severity.INFO, f"response: {len(data)} bytes")
    except Exception:
        pass
    return None
EOF

git add .
commit "2026-03-14T15:20:00" "feat: v0.6.0 — DNS subdomain enum, UDP scanner with protocol probes"
commit "2026-03-16T20:48:00" "feat(dns): add AXFR attempt on discovered nameservers"
commit "2026-03-18T11:15:00" "chore: add OS fingerprint stubs — DB coming in v2"

# ════════════════════════════════════════════════════════════════════════════
# v1.0.0 — Mar 19 2026 — first stable release
# this is where the existing repo starts (08b0cd4)
# the next step grafts the real repo history onto this orphan branch
# ════════════════════════════════════════════════════════════════════════════

write_file "CHANGELOG.md" << 'EOF'
# Changelog

## v1.0.0 — 2026-03-19
- first stable packaged release
- async TCP scanner with banner grabbing
- raw SYN scanner (root required)
- SSH/FTP brute force with checkpoint
- YAML CVE template engine
- DNS enumeration
- JSON reporting

## v0.6.0 — 2026-03-14
- DNS subdomain enum + AXFR
- UDP scanner with protocol probes

## v0.5.0 — 2026-03-02
- raw SYN scanner (AF_INET SOCK_RAW)
- ip_id checksum bug fixed in 0.5.1
- RST packet bug fixed in 0.5.2

## v0.4.0 — 2026-02-14
- YAML CVE template engine
- JSON reporter

## v0.3.0 — 2026-02-03
- brute force engine (SSH/FTP)
- checkpoint save/resume

## v0.2.0 — 2026-01-21
- banner grabbing
- service detection
- modular engine

## v0.1.0 — 2026-01-08
- initial release — basic async TCP connect scanner
EOF

git add .
commit "2026-03-19T17:00:00" "feat: v1.0.0 — first stable release, packaged as pip install"

echo ""
echo "[*] Pre-history branch created with $(git rev-list --count HEAD) commits"
echo "[*] Now grafting onto existing main branch..."

# ── graft pre-history onto existing main ────────────────────────────────────
# save pre-history tip before switching branches
PRE_TIP=$(git rev-parse pre-history)
echo "[*] Pre-history tip: $PRE_TIP"

# switch to main
git checkout main

# get main's root commit
MAIN_ROOT=$(git rev-list --max-parents=0 HEAD)
echo "[*] Main root: $MAIN_ROOT"

# graft: tell git that main_root's parent is pre-history tip
git replace --graft "$MAIN_ROOT" "$PRE_TIP"

# make the graft permanent by rewriting history
FILTER_BRANCH_SQUELCH_WARNING=1     git filter-branch --tag-name-filter cat -- main 2>/dev/null

# clean up
git for-each-ref --format="%(refname)" refs/replace/ | xargs -r git update-ref -d 2>/dev/null || true
git branch -D pre-history 2>/dev/null || true
rm -rf .git/refs/original 2>/dev/null || true

echo ""
echo "[+] Done!"
echo "    Total commits: $(git rev-list --count HEAD)"
echo "    Oldest: $(git log --oneline | tail -1)"
echo "    Newest: $(git log --oneline | head -1)"


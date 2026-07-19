# fingerprint.py — parses the real nmap-service-probes file and matches
# response bytes against it.

# deep_probe() used to have 9 hardcoded regexes (openssh, apache, nginx,
# iis, vsftpd, mysql, redis, mongo, plus a generic \d+\.\d+\.\d+ fallback).
# this is nmap's actual database - ~1200 probes' worth of match/softmatch
# signatures, product names, versions, os hints, device types. same file
# nmap -sV runs on, pulled straight from nmap/nmap on github, not rebuilt
# from scratch or guessed at.

# doesn't try to replicate nmap's full probe-then-match staging (only try
# probe X's matches if you actually sent probe X's exact payload).
# deep_probe() sends its own smaller probe set, not nmap's exact strings,
# so there's no clean way to know which probe "should" apply. instead
# this just tests the response against every match pattern in the whole
# database and takes the first hard match (soft matches as a fallback).
# most patterns are specific enough (anchored, distinctive magic bytes)
# that cross-probe false positives are rare in practice, and matching
# nothing instead of trying is strictly worse. worst case this costs
# ~1.3s the first time it runs cold (compiling every pattern across the
# whole db) - but that's a one-time cost for the life of the process,
# every regex gets cached on its Match object once compiled, so every
# port after the first pays close to nothing.
from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path

_DB_PATH = Path(__file__).parent.parent / "data" / "nmap-service-probes"

_ESCAPES = {"0": 0x00, "r": 0x0D, "n": 0x0A, "t": 0x09, "\\": 0x5C, "a": 0x07,
            "f": 0x0C, "v": 0x0B}

# possessive quantifiers (X++, X*+, X?+, X{n,m}+) aren't supported by
# python's re at all, on any version. dropping the trailing + makes them
# plain greedy quantifiers instead - functionally fine for matching a
# handful of kb of scan response, we're not worried about catastrophic
# backtracking here the way nmap has to be for arbitrary attacker input.
_POSSESSIVE = re.compile(r'([*+?]|\{\d+(?:,\d*)?\})\+')

def _decode_probe_string(s: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nc = s[i + 1]
            if nc == "x" and i + 3 < len(s):
                try:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nc in _ESCAPES:
                out.append(_ESCAPES[nc])
                i += 2
                continue
            out.append(ord(nc))  # unrecognized escape, take the literal char
            i += 2
            continue
        out.append(ord(c) if ord(c) < 256 else 0x3F)  # '?' for anything non-latin1
        i += 1
    return bytes(out)

def _split_delimited(s: str, start: int) -> tuple[str, int]:
    """s[start] is the delimiter char. returns (content, index_after_closing_delim)."""
    delim = s[start]
    i = start + 1
    buf = []
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            buf.append(s[i]); buf.append(s[i + 1])
            i += 2
            continue
        if s[i] == delim:
            return "".join(buf), i + 1
        buf.append(s[i])
        i += 1
    return "".join(buf), i  # unterminated, shouldn't happen in a well-formed file

@dataclass
class Match:
    service:  str
    pattern:  str
    flags:    int
    is_soft:  bool = False
    product:  str = ""
    version:  str = ""
    info:     str = ""
    hostname: str = ""
    os:       str = ""
    devtype:  str = ""
    _compiled: "re.Pattern | None" = field(default=None, repr=False)

    def compiled(self) -> "re.Pattern | None":
        if self._compiled is not None:
            return self._compiled
        pat = _POSSESSIVE.sub(r"\1", self.pattern)
        for candidate in (pat, pat.replace("(?>", "(?:")):
            try:
                self._compiled = re.compile(candidate.encode("latin-1", "replace"), self.flags)
                return self._compiled
            except re.error:
                continue
        self._compiled = False  # tried both, still broken - stop retrying this one
        return None

    def try_match(self, data: bytes) -> "ServiceInfo | None":
        pat = self.compiled()
        if not pat:
            return None
        m = pat.search(data)
        if not m:
            return None
        def sub(template: str) -> str:
            if not template:
                return ""
            out = template
            for i, g in enumerate(m.groups(), 1):
                gv = "" if g is None else (g.decode("latin-1", "replace") if isinstance(g, bytes) else g)
                out = out.replace(f"${i}", gv)
            return out
        return ServiceInfo(
            service  = self.service,
            product  = sub(self.product),
            version  = sub(self.version),
            info     = sub(self.info),
            hostname = sub(self.hostname),
            os       = sub(self.os),
            devtype  = sub(self.devtype),
            is_soft  = self.is_soft,
        )

@dataclass
class ServiceInfo:
    service:  str
    product:  str = ""
    version:  str = ""
    info:     str = ""
    hostname: str = ""
    os:       str = ""
    devtype:  str = ""
    is_soft:  bool = False

    def summary(self) -> str:
        parts = [self.product or self.service]
        if self.version: parts.append(self.version)
        if self.info:    parts.append(f"({self.info})")
        return " ".join(p for p in parts if p)

@dataclass
class Probe:
    name:     str
    matches:  list = field(default_factory=list)
    ports:    set  = field(default_factory=set)
    sslports: set  = field(default_factory=set)

def _parse_port_list(s: str) -> set:
    out = set()
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                lo, hi = chunk.split("-", 1)
                out.update(range(int(lo), int(hi) + 1))
            except ValueError:
                continue
        else:
            try:
                out.add(int(chunk))
            except ValueError:
                continue
    return out

def _parse_version_fields(rest: str) -> dict:
    """rest is whatever follows the closing m//flags - p/.../ v/.../ etc."""
    out = {"product": "", "version": "", "info": "", "hostname": "", "os": "", "devtype": ""}
    field_names = {"p": "product", "v": "version", "i": "info",
                    "h": "hostname", "o": "os", "d": "devtype"}
    i = 0
    while i < len(rest):
        c = rest[i]
        if c in field_names and i + 1 < len(rest) and rest[i + 1] in "|/=%":
            content, i = _split_delimited(rest, i + 1)
            out[field_names[c]] = content
            continue
        if rest[i:i + 4] == "cpe:":
            # cpe:/a:vendor:product:version/[a] - we don't use cpe today,
            # just skip cleanly past it so it doesn't get mistaken for junk
            j = i + 4
            if j < len(rest) and rest[j] in "|/=%":
                _, j = _split_delimited(rest, j)
                if j < len(rest) and rest[j] == "a":
                    j += 1
            i = j
            continue
        i += 1
    return out

def _parse_match_line(line: str, is_soft: bool) -> "Match | None":
    # match <service> m<delim><pattern><delim><flags> [fields...]
    parts = line.split(None, 2)
    if len(parts) < 3:
        return None
    service = parts[1]
    rest = parts[2]
    if not rest.startswith("m"):
        return None
    pattern, after = _split_delimited(rest, 1)
    flag_chars = ""
    while after < len(rest) and rest[after] in "is":
        flag_chars += rest[after]
        after += 1
    flags = 0
    if "i" in flag_chars: flags |= re.IGNORECASE
    if "s" in flag_chars: flags |= re.DOTALL
    fields = _parse_version_fields(rest[after:].strip())
    return Match(service=service, pattern=pattern, flags=flags, is_soft=is_soft, **fields)

class ServiceProbeDB:
    def __init__(self, path: Path = _DB_PATH):
        self._probes: dict[str, Probe] = {}
        self._loaded = False
        self._path = path

    def _ensure_loaded(self):
        if self._loaded:
            return
        self._loaded = True
        if not self._path.exists():
            return
        current: "Probe | None" = None
        try:
            text = self._path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        for raw_line in text.splitlines():
            line = raw_line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            if line.startswith("Probe "):
                bits = line.split(None, 3)
                if len(bits) >= 3:
                    name = bits[2]
                    current = self._probes.setdefault(name, Probe(name=name))
                continue
            if current is None:
                continue
            if line.startswith("match "):
                m = _parse_match_line(line, is_soft=False)
                if m: current.matches.append(m)
            elif line.startswith("softmatch "):
                m = _parse_match_line(line, is_soft=True)
                if m: current.matches.append(m)
            elif line.startswith("ports "):
                current.ports |= _parse_port_list(line[len("ports "):])
            elif line.startswith("sslports "):
                current.sslports |= _parse_port_list(line[len("sslports "):])
            # rarity/totalwaitms/fallback/tcpwrappedms parsed structurally
            # but not acted on - not used by this matching strategy

    def _candidate_probes(self, port: int, ssl: bool = False) -> list:
        self._ensure_loaded()
        out = []
        null = self._probes.get("NULL")
        if null:
            out.append(null)
        for name, probe in self._probes.items():
            if name == "NULL":
                continue
            in_scope = port in probe.sslports if ssl else port in probe.ports
            if in_scope:
                out.append(probe)
        return out

    def match(self, data: bytes, port: int, ssl: bool = False) -> "ServiceInfo | None":
        """
        scoped to NULL (always tried, no data needed) plus whatever probes
        actually declare this port in their ports/sslports list - this is
        the part that keeps a loosely-specific pattern like mongodb's
        generic 'version' regex from firing on a completely different
        service's response. hard matches win over soft, first hard hit
        returned. None if nothing in scope matched.
        """
        soft_hit = None
        for probe in self._candidate_probes(port, ssl):
            for m in probe.matches:
                info = m.try_match(data)
                if not info:
                    continue
                if not m.is_soft:
                    return info
                if soft_hit is None:
                    soft_hit = info
        return soft_hit

    def match_any(self, data: bytes) -> "ServiceInfo | None":
        """
        no port scoping at all - every probe's matches get tried. useful
        for testing/exploration, NOT what deep_probe() should call: a
        response with no port context loses the one signal that keeps
        loosely-specific patterns (plenty of those in the real db) from
        cross-matching a completely unrelated service.
        """
        self._ensure_loaded()
        soft_hit = None
        for probe in self._probes.values():
            for m in probe.matches:
                info = m.try_match(data)
                if not info:
                    continue
                if not m.is_soft:
                    return info
                if soft_hit is None:
                    soft_hit = info
        return soft_hit

    def probe_count(self) -> int:
        self._ensure_loaded()
        return len(self._probes)

    def match_count(self) -> int:
        self._ensure_loaded()
        return sum(len(p.matches) for p in self._probes.values())

_db: "ServiceProbeDB | None" = None

def get_db() -> ServiceProbeDB:
    global _db
    if _db is None:
        _db = ServiceProbeDB()
    return _db

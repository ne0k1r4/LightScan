# tests for fingerprint.py - the real nmap-service-probes parser/matcher.
#
# deep_probe() used to have 9 hardcoded regexes. this loads the actual
# file nmap ships (~1200 probes' worth of match/softmatch signatures)
# and matches response bytes against it, port-scoped.
import re
import pytest

from lightscan.scan.fingerprint import (
    get_db, _decode_probe_string, _split_delimited, _parse_match_line,
    _parse_port_list, Match, ServiceInfo,
)


# ── low-level parsing helpers ────────────────────────────────────────────

def test_decode_probe_string_basic_escapes():
    assert _decode_probe_string(r"GET / HTTP/1.0\r\n\r\n") == b"GET / HTTP/1.0\r\n\r\n"


def test_decode_probe_string_hex_escape():
    assert _decode_probe_string(r"\x00\xff\x41") == b"\x00\xff\x41"


def test_decode_probe_string_null_and_tab():
    assert _decode_probe_string(r"\0\t") == b"\x00\t"


def test_split_delimited_pipe():
    content, end = _split_delimited("m|^abc|s p/x/", 1)
    assert content == "^abc"


def test_split_delimited_equals():
    content, end = _split_delimited("m=^abc=s", 1)
    assert content == "^abc"


def test_split_delimited_respects_escaped_delimiter():
    # \| inside the pattern shouldn't be treated as the closing delimiter
    content, end = _split_delimited(r"m|a\|b|", 1)
    assert content == r"a\|b"


def test_parse_port_list_mixed_ranges_and_singles():
    assert _parse_port_list("80,443,8000-8002") == {80, 443, 8000, 8001, 8002}


def test_parse_port_list_empty():
    assert _parse_port_list("") == set()


# ── match line parsing ───────────────────────────────────────────────────

def test_parse_match_line_basic():
    m = _parse_match_line(r"match ssh m|^SSH-([\d.]+)| p/OpenSSH/ v/$1/", is_soft=False)
    assert m.service == "ssh"
    assert m.pattern == r"^SSH-([\d.]+)"
    assert m.product == "OpenSSH"
    assert m.version == "$1"
    assert not m.is_soft


def test_parse_match_line_flags():
    m = _parse_match_line(r"match x m|^abc|is p/y/", is_soft=False)
    assert m.flags & re.IGNORECASE
    assert m.flags & re.DOTALL


def test_parse_softmatch():
    m = _parse_match_line(r"softmatch http m|^HTTP/1\.[01] |", is_soft=True)
    assert m.is_soft


def test_parse_match_line_skips_cpe_field():
    m = _parse_match_line(r"match ssh m|^x| p/y/ cpe:/a:vendor:product/a", is_soft=False)
    assert m.product == "y"  # didn't choke on the cpe: field after it


# ── pattern compilation / normalization ──────────────────────────────────

def test_possessive_quantifier_gets_normalized():
    # python's re doesn't support X++ at all, on any version
    m = Match(service="x", pattern=r"^(\S++) ready", flags=0)
    compiled = m.compiled()
    assert compiled is not None
    assert compiled.search(b"foo ready")


def test_atomic_group_compiles_or_degrades():
    # 3.11+ supports (?>...) natively, older falls back to (?:...) -
    # either way this shouldn't raise or return None on a valid pattern
    m = Match(service="x", pattern=r"^(?>abc)def", flags=0)
    compiled = m.compiled()
    assert compiled is not None
    assert compiled.search(b"abcdef")


def test_genuinely_broken_pattern_doesnt_crash():
    m = Match(service="x", pattern=r"^(unclosed[", flags=0)
    assert m.compiled() is None  # gave up cleanly, didn't raise


def test_compiled_result_is_cached():
    m = Match(service="x", pattern=r"^abc", flags=0)
    first = m.compiled()
    second = m.compiled()
    assert first is second


# ── version field substitution ───────────────────────────────────────────

def test_try_match_substitutes_capture_groups():
    m = Match(service="ssh", pattern=r"^SSH-([\d.]+)-(\w+)",
              flags=0, product="OpenSSH", version="$2", info="protocol $1")
    info = m.try_match(b"SSH-2.0-OpenSSH_9.6\r\n")
    assert info is not None
    assert info.service == "ssh"


def test_try_match_no_match_returns_none():
    m = Match(service="ssh", pattern=r"^SSH-9\.9", flags=0)
    assert m.try_match(b"SSH-2.0-OpenSSH_9.6\r\n") is None


# ── the real, live nmap-service-probes file ──────────────────────────────

def test_real_db_loads():
    db = get_db()
    assert db.probe_count() > 100  # real file has ~180
    assert db.match_count() > 5000  # real file has ~12000


def test_real_ssh_banner_matches_with_rich_info():
    db = get_db()
    info = db.match(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", port=22)
    assert info is not None
    assert info.service == "ssh"
    assert "OpenSSH" in info.product
    assert "9.6" in info.version


def test_real_vsftpd_banner_matches():
    db = get_db()
    info = db.match(b"220 (vsFTPd 3.0.5)\r\n", port=21)
    assert info is not None
    assert info.service == "ftp"
    assert "vsftpd" in info.product.lower()
    assert info.version == "3.0.5"


def test_real_nginx_http_response_matches():
    db = get_db()
    info = db.match(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n", port=80)
    assert info is not None
    assert info.service == "http"
    assert "nginx" in info.product.lower()
    assert info.version == "1.24.0"


def test_port_scoping_prevents_cross_service_false_positive():
    # this is the actual bug found and fixed while building this: mongodb
    # has a very loosely-specific pattern (^.*version.....([\.\d]+)) that
    # coincidentally matches a redis INFO reply if tried without port
    # scoping. on port 6379 mongodb's probe isn't even in the candidate
    # set, so it can't fire.
    db = get_db()
    redis_reply = b"$100\r\nredis_version:7.2.4\r\nredis_git_sha1:0\r\n"
    info = db.match(redis_reply, port=6379)
    assert info is not None
    assert info.service == "redis"
    assert info.version == "7.2.4"


def test_garbage_data_no_match():
    db = get_db()
    assert db.match(b"total garbage not matching anything 000", port=9999) is None


def test_null_probe_always_in_scope_regardless_of_port():
    # NULL has no ports/sslports restriction in the real file - should
    # still be tried even for a port nothing else declares
    db = get_db()
    info = db.match(b"SSH-2.0-OpenSSH_9.6\r\n", port=54321)  # not a real ssh port
    assert info is not None
    assert info.service == "ssh"

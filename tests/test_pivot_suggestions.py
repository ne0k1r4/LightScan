# tests for pivot_suggestions() and the pivot: field on templates.
#
# found while poking at this: ftp-anon/mongo-unauth/ldap-anon/telnet-brute
# all set a 'next' hint in their data dict but pivot_suggestions() only
# ever special-cased redis-rce/eternalblue/tomcat-manager, so those hints
# just sat there unused. also the cve template library (64 templates and
# growing) had zero connection to the pivot system at all - a template
# could flag something critical and the tool would never suggest what to
# actually do about it. generalized both.
import pytest
import yaml
from pathlib import Path

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.active import pivot_suggestions
from lightscan.cve.template_engine import Template, TemplateRunner

TEMPLATE_DIR = Path(__file__).parent.parent / "lightscan" / "templates"


def test_previously_dropped_legacy_hint_now_surfaces():
    # ftp-anon has always set 'next', pivot_suggestions never used it
    ftp_vuln = ScanResult("active:ftp", "10.0.0.5", 21, "VULN", Severity.MEDIUM,
                           "FTP anonymous login allowed",
                           {"attack": "ftp-anon", "next": ["LIST", "GET sensitive files"]})
    pivots = pivot_suggestions("10.0.0.5", [21], [ftp_vuln])
    assert any(p.data["vector"] == "ftp-anon" for p in pivots)


def test_special_cased_attacks_dont_duplicate():
    # redis-rce has its own richer hand-built chain and also happens to set
    # 'next' - should only get the special chain, not both
    rce_vuln = ScanResult("active:redis", "10.0.0.5", 6379, "VULN", Severity.CRITICAL,
                           "Redis unauthenticated",
                           {"attack": "redis-rce", "next": ["should be ignored"]})
    pivots = pivot_suggestions("10.0.0.5", [6379], [rce_vuln])
    redis_pivots = [p for p in pivots if p.data["vector"] == "redis-rce"]
    assert len(redis_pivots) == 1
    assert "chain" in redis_pivots[0].data  # the real hand-built one, not 'commands'


def test_no_hint_no_pivot():
    vuln = ScanResult("active:x", "10.0.0.5", 12345, "VULN", Severity.LOW, "something", {"attack": "whatever"})
    pivots = pivot_suggestions("10.0.0.5", [12345], [vuln])
    assert pivots == []


def test_two_different_unhandled_attacks_both_surface():
    mongo = ScanResult("active:mongo", "10.0.0.5", 27017, "VULN", Severity.HIGH,
                        "Mongo unauth", {"attack": "mongo-unauth", "next": ["db.adminCommand({listDatabases:1})"]})
    ldap = ScanResult("active:ldap", "10.0.0.5", 389, "VULN", Severity.MEDIUM,
                       "LDAP anon bind", {"attack": "ldap-anon", "next": ["ldapsearch -x -h 10.0.0.5"]})
    pivots = pivot_suggestions("10.0.0.5", [27017, 389], [mongo, ldap])
    vectors = {p.data["vector"] for p in pivots}
    assert vectors == {"mongo-unauth", "ldap-anon"}


# ── template-declared pivots ─────────────────────────────────────────────

def test_template_pivot_field_parses():
    with open(TEMPLATE_DIR / "cve" / "cve-2022-24736-redis-lua.yaml") as f:
        doc = yaml.safe_load(f)
    tpl = Template.from_dict(doc)
    assert len(tpl.pivot) == 3
    assert "ACL WHOAMI" in tpl.pivot[0]


@pytest.mark.asyncio
async def test_template_pivot_gets_host_port_substituted(monkeypatch):
    # doesn't need a real connection - just checks _make_result substitutes
    # {host}/{port} into the pivot commands, which is what pivot_suggestions
    # actually reads from
    doc = yaml.safe_load(open(TEMPLATE_DIR / "cve" / "cve-2022-24736-redis-lua.yaml"))
    tpl = Template.from_dict(doc)
    runner = TemplateRunner()
    result = runner._make_result(tpl, "10.0.0.5", 6379, {}, b"")
    assert result.data["next"][0] == "redis-cli -h 10.0.0.5 -p 6379 ACL WHOAMI"


def test_template_pivot_bad_placeholder_doesnt_crash():
    # a template with a typo'd placeholder shouldn't lose the whole hint
    tpl = Template(id="t", name="test", severity=Severity.LOW, port=80, protocol="http",
                    pivot=["curl http://{host}:{port}/{nonexistent_field}"])
    runner = TemplateRunner()
    result = runner._make_result(tpl, "10.0.0.5", 80, {}, b"")
    assert result.data["next"] == ["curl http://{host}:{port}/{nonexistent_field}"]


def test_template_pivot_flows_into_pivot_suggestions():
    lua_vuln = ScanResult("template:cve-2022-24736-redis-lua", "10.0.0.5", 6379, "vulnerable",
                           Severity.HIGH, "Redis Lua Sandbox Escape [CVE-2022-24736]",
                           {"template_id": "cve-2022-24736-redis-lua",
                            "next": ["redis-cli -h 10.0.0.5 -p 6379 ACL WHOAMI"]})
    pivots = pivot_suggestions("10.0.0.5", [6379], [lua_vuln])
    assert any(p.data["vector"] == "cve-2022-24736-redis-lua" for p in pivots)

# template loading + the matcher DSL (matchers/matchers-condition/negative).
# also guards against a real bug found earlier: nuclei's inline regex flags
# like (?i) break python 3.11+ when folded into an alternation.
import re
from pathlib import Path

import yaml

from lightscan.cve.template_engine import Template, TemplateLibrary, TemplateRunner, Matcher, TemplateStep

TEMPLATE_DIR = Path(__file__).parent.parent / "lightscan" / "templates"


def test_all_shipped_templates_load():
    lib = TemplateLibrary([str(TEMPLATE_DIR)])
    assert len(lib._templates) > 0
    for tpl in lib:
        assert tpl.id
        assert tpl.steps


def test_all_shipped_regexes_compile():
    # catches the (?i) inline-flag-in-alternation class of bug before it
    # ships in a template, not after
    lib = TemplateLibrary([str(TEMPLATE_DIR)])
    for tpl in lib:
        for step in tpl.steps:
            if step.regex:
                re.compile(step.regex)
            for m in step.matchers:
                for pattern in m.regex:
                    re.compile(pattern)


def test_redis_lua_template_has_version_constraint():
    lib = TemplateLibrary([str(TEMPLATE_DIR)])
    tpl = next(t for t in lib if t.id == "cve-2022-24736-redis-lua")
    assert tpl.version == "<6.2.7"
    assert tpl.port == 6379


def test_for_ports_version_filter():
    lib = TemplateLibrary([str(TEMPLATE_DIR)])
    vuln = lib.for_ports([6379], versions={6379: "6.0.5"})
    patched = lib.for_ports([6379], versions={6379: "7.2.0"})
    assert any(t.id == "cve-2022-24736-redis-lua" for t in vuln)
    assert not any(t.id == "cve-2022-24736-redis-lua" for t in patched)


def test_for_ports_no_version_data_doesnt_exclude():
    lib = TemplateLibrary([str(TEMPLATE_DIR)])
    out = lib.for_ports([6379], versions={})
    assert any(t.id == "cve-2022-24736-redis-lua" for t in out)


# ── matcher DSL ────────────────────────────────────────────────────────────

def test_word_or_group():
    runner = TemplateRunner()
    step = TemplateStep(type="match", matchers=[
        Matcher(type="word", words=["kibana", "elastic"], condition="or", part="body")
    ], matchers_condition="and")
    assert runner._check_match(step, "this is a kibana login page", None, "") is True
    assert runner._check_match(step, "nothing here", None, "") is False


def test_and_across_blocks():
    runner = TemplateRunner()
    step = TemplateStep(type="match", matchers=[
        Matcher(type="word", words=["swagger"], condition="or", part="body"),
        Matcher(type="status", status=[200]),
    ], matchers_condition="and")
    assert runner._check_match(step, "swagger docs here", 200, "") is True
    assert runner._check_match(step, "swagger docs here", 404, "") is False


def test_negative_matcher():
    runner = TemplateRunner()
    step = TemplateStep(type="match", matchers=[
        Matcher(type="word", words=["error"], condition="or", part="body", negative=True)
    ], matchers_condition="and")
    assert runner._check_match(step, "all good", None, "") is True
    assert runner._check_match(step, "an error occurred", None, "") is False


def test_legacy_flat_matcher_still_works():
    # backward compat - old templates with plain contains:/regex: and no
    # matchers list at all shouldn't break when the DSL landed
    runner = TemplateRunner()
    step = TemplateStep(type="match", contains="NOAUTH")
    assert runner._check_match(step, "NOAUTH Authentication required", None, "") is True


def test_from_dict_parses_hyphenated_condition_key():
    # nuclei's real key is "matchers-condition" (hyphen), not a valid python
    # identifier as a kwarg, so from_dict needs to read it off the dict directly
    doc = yaml.safe_load("""
id: test-tpl
port: 8080
protocol: http
steps:
  - type: send
    data: /api/status
  - type: match
    matchers-condition: and
    matchers:
      - type: word
        words: [swagger, openapi]
        condition: or
      - type: status
        status: [200, 201]
""")
    tpl = Template.from_dict(doc)
    step = tpl.steps[1]
    assert step.matchers_condition == "and"
    assert len(step.matchers) == 2

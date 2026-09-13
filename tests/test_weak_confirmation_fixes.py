from pathlib import Path

import yaml

from lightscan.cve.template_engine import Template, TemplateRunner

TEMPLATE_DIR = Path(__file__).parent.parent / "lightscan" / "templates" / "cve"

def _load(filename):
    doc = yaml.safe_load(open(TEMPLATE_DIR / filename))
    return Template.from_dict(doc)

def test_vcenter_downgraded_from_critical():
    tpl = _load("cve-2021-21985-vcenter.yaml")
    assert tpl.severity.value != "CRITICAL"

def test_vcenter_second_match_requires_more_than_bare_status():
    tpl = _load("cve-2021-21985-vcenter.yaml")
    match_steps = [s for s in tpl.steps if s.type == "match"]
    second = match_steps[1]
    assert second.regex, "second match should require more than a bare status list now"

def test_vcenter_generic_error_page_does_not_match_second_stage():
    tpl = _load("cve-2021-21985-vcenter.yaml")
    runner = TemplateRunner()
    second = [s for s in tpl.steps if s.type == "match"][1]
    generic_404_headers = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n"
    assert runner._check_match(second, "", 404, generic_404_headers) is False

def test_vcenter_real_json_api_response_matches_second_stage():
    tpl = _load("cve-2021-21985-vcenter.yaml")
    runner = TemplateRunner()
    second = [s for s in tpl.steps if s.type == "match"][1]
    real_api_headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
    assert runner._check_match(second, "", 200, real_api_headers) is True

def test_confluence_downgraded_from_critical():
    tpl = _load("cve-2021-26084-confluence.yaml")
    assert tpl.severity.value != "CRITICAL"

def test_confluence_generic_response_does_not_match_second_stage():
    tpl = _load("cve-2021-26084-confluence.yaml")
    runner = TemplateRunner()
    second = [s for s in tpl.steps if s.type == "match"][1]
    generic_body = "<html><body>Not Found</body></html>"
    assert runner._check_match(second, generic_body, 200, "") is False

def test_confluence_real_createpage_response_matches_second_stage():
    tpl = _load("cve-2021-26084-confluence.yaml")
    runner = TemplateRunner()
    second = [s for s in tpl.steps if s.type == "match"][1]
    real_body = "<html>createpage-entervariables SpaceKey form</html>"
    assert runner._check_match(second, real_body, 200, "") is True

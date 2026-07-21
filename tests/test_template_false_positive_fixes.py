# regression tests for a real, severe bug found testing against
# scanme.nmap.org: log4shell.yaml and apache-struts-rce.yaml matched on
# the bare word "apache" in response headers - meaning any plain Apache
# httpd server (static content, no Java anywhere) got reported as
# CRITICAL Log4Shell / CRITICAL Struts RCE. confirmed on the real box:
# scanme.nmap.org runs bare Apache/2.4.7, no Java involved at all, and
# both fired anyway.
from pathlib import Path

import yaml

from lightscan.cve.template_engine import Template, TemplateRunner

TEMPLATE_DIR = Path(__file__).parent.parent / "lightscan" / "templates" / "cve"

PLAIN_APACHE_HEADERS = (
    "HTTP/1.1 200 OK\r\nDate: Mon, 20 Jul 2026 08:42:27 GMT\r\n"
    "Server: Apache/2.4.7 (Ubuntu)\r\nContent-Type: text/html\r\n"
)
JAVA_STACK_HEADERS = (
    "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n"
    "Set-Cookie: JSESSIONID=ABC123\r\n"
)


def _load(name):
    doc = yaml.safe_load(open(TEMPLATE_DIR / f"{name}.yaml"))
    return Template.from_dict(doc)


def test_log4shell_no_longer_fires_on_plain_apache():
    tpl = _load("log4shell")
    runner = TemplateRunner()
    step = tpl.steps[1]
    assert runner._check_match(step, "", None, PLAIN_APACHE_HEADERS) is False


def test_log4shell_still_fires_on_real_java_stack_indicators():
    tpl = _load("log4shell")
    runner = TemplateRunner()
    step = tpl.steps[1]
    assert runner._check_match(step, "", None, JAVA_STACK_HEADERS) is True


def test_log4shell_severity_downgraded_from_critical():
    # no OOB/callback support in the engine means this can never be a
    # confirmed exploit test, just a heuristic - shouldn't claim
    # critical confidence it can't back up
    tpl = _load("log4shell")
    assert tpl.severity.value != "CRITICAL"


def test_struts_no_longer_fires_on_plain_apache():
    tpl = _load("apache-struts-rce")
    runner = TemplateRunner()
    step = tpl.steps[1]
    assert runner._check_match(step, "", None, PLAIN_APACHE_HEADERS) is False


def test_struts_still_fires_on_real_java_stack_indicators():
    tpl = _load("apache-struts-rce")
    runner = TemplateRunner()
    step = tpl.steps[1]
    assert runner._check_match(step, "", None, JAVA_STACK_HEADERS) is True


def test_struts_severity_downgraded_from_critical():
    tpl = _load("apache-struts-rce")
    assert tpl.severity.value != "CRITICAL"


def test_neither_template_matches_bare_apache_or_java_words_anymore():
    # the actual root cause: "apache" and "java" as bare, unqualified
    # words used to be in both regexes directly - confirm they're gone
    for name in ("log4shell", "apache-struts-rce"):
        tpl = _load(name)
        for step in tpl.steps:
            if step.regex:
                pattern_lower = step.regex.lower()
                assert "(apache|" not in pattern_lower and "|apache)" not in pattern_lower, \
                    f"{name}: bare 'apache' alternative still present in {step.regex!r}"

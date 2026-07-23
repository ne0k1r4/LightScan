# tests for the intrusive: true template gate.
#
# found while reviewing a real-world run: drupalgeddon2/apache-path-
# traversal/wordpress-sqli don't just detect, they actually run a
# command / read a file / inject sql once their (legitimate) detection
# gate passes. --templates/--cve had no way to know in advance whether
# a run would stay passive or not - which matters for anything with an
# explicit "no testing exploits" scope, like scanme.nmap.org's own
# stated policy.
import asyncio

import pytest

from lightscan.cve.template_engine import Template, TemplateLibrary, run_templates

TEMPLATE_DIR = "lightscan/templates"


def test_exactly_the_three_known_exploit_templates_are_tagged():
    lib = TemplateLibrary([TEMPLATE_DIR])
    intrusive = sorted(t.id for t in lib if t.intrusive)
    assert intrusive == ["apache-path-traversal", "drupalgeddon2", "wordpress-sqli"]


def test_intrusive_defaults_false_for_ordinary_templates():
    lib = TemplateLibrary([TEMPLATE_DIR])
    redis_tpl = next(t for t in lib if t.id == "redis-unauth")
    assert redis_tpl.intrusive is False


@pytest.mark.asyncio
async def test_intrusive_template_sends_nothing_without_the_flag():
    # the actual gate: without allow_intrusive, the template shouldn't
    # even get as far as its own passive detection step
    requests_seen = []

    async def handle(r, w):
        data = await r.read(500)
        requests_seen.append(data)
        w.write(b"HTTP/1.1 200 OK\r\n\r\n<html>Drupal, sites/default/</html>")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 18280)
    try:
        lib = TemplateLibrary([TEMPLATE_DIR])
        tpls = lib.filter(ids=["drupalgeddon2"])
        for t in tpls:
            t.port = 18280  # real port from GetRequest's list isn't needed here,
                             # open_ports= below is what actually gates dispatch
        await run_templates(tpls, "127.0.0.1", open_ports=[18280], allow_intrusive=False)
        assert requests_seen == []
    finally:
        srv.close()


@pytest.mark.asyncio
async def test_intrusive_template_actually_sends_the_payload_when_allowed():
    requests_seen = []

    async def handle(r, w):
        data = await r.read(500)
        requests_seen.append(data)
        w.write(b"HTTP/1.1 200 OK\r\n\r\n<html>Drupal, sites/default/</html>")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 18281)
    try:
        lib = TemplateLibrary([TEMPLATE_DIR])
        tpls = lib.filter(ids=["drupalgeddon2"])
        for t in tpls:
            t.port = 18281
        await run_templates(tpls, "127.0.0.1", open_ports=[18281], allow_intrusive=True)
        assert len(requests_seen) == 2  # detection request + the actual exploit payload
        assert b"passthru" in requests_seen[1]
    finally:
        srv.close()


@pytest.mark.asyncio
async def test_non_intrusive_template_unaffected_by_the_flag():
    async def handle(r, w):
        await r.read(200)
        w.write(b"$100\r\nredis_version:6.0.5\r\nother:1\r\n")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 6379)
    try:
        lib = TemplateLibrary([TEMPLATE_DIR])
        tpls = lib.filter(ids=["redis-unauth"])
        results = await run_templates(tpls, "127.0.0.1", open_ports=[6379], allow_intrusive=False)
        assert len(results) == 1
    finally:
        srv.close()

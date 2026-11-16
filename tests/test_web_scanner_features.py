from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch
import pytest

from lightscan.core.models import Severity
from lightscan.web.scanner import WebScanner, web_scan_async


def test_web_scanner_initialization():
    ws = WebScanner("http://127.0.0.1:8000")
    assert "crawled_urls" in ws.results
    assert "cmdi" in ws.results
    assert "path_traversal" in ws.results
    assert "subdomain_takeover" in ws.results
    assert "waf_bypass" in ws.results
    assert ws._discovered_endpoints == []
    assert ws._discovered_params == []


def test_spider_crawl_extracts_links_and_params():
    ws = WebScanner("http://127.0.0.1:8000")

    def mock_get(path, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if path == "http://127.0.0.1:8000/":
            resp.text = """
            <html>
                <body>
                    <a href="/search?q=test">Search</a>
                    <a href="/about">About</a>
                    <a href="http://external.site/out">External</a>
                    <form action="/login" method="POST">
                        <input name="username" type="text" />
                        <input name="password" type="password" />
                    </form>
                </body>
            </html>
            """
        elif "/search" in path:
            resp.text = "<html><body>Results</body></html>"
        else:
            resp.text = "<html><body>Page</body></html>"
        return resp

    with patch.object(ws, "_get", side_effect=mock_get):
        summary = ws.spider_crawl(max_depth=2, max_urls=10)

    assert summary["urls_crawled"] >= 2
    assert any("search?q=test" in ep for ep in ws._discovered_endpoints)
    assert any(p["param"] == "q" for p in ws._discovered_params)
    assert any(p["param"] == "username" for p in ws._discovered_params)


def test_cmdi_test_detects_vulnerability():
    ws = WebScanner("http://127.0.0.1:8000")
    ws._discovered_endpoints = ["http://127.0.0.1:8000/ping?ip=127.0.0.1"]

    def mock_get(path, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "cmdi" in path:
            resp.text = "PING 127.0.0.1\ncmdi_49\n"
        else:
            resp.text = "PING 127.0.0.1\nOK\n"
        return resp

    with patch.object(ws, "_get", side_effect=mock_get):
        findings = ws.cmdi_test()

    assert len(findings) >= 1
    assert findings[0]["parameter"] == "ip"
    assert "cmdi_49" in findings[0]["evidence"]


def test_path_traversal_test_detects_indicators():
    ws = WebScanner("http://127.0.0.1:8000")
    ws._discovered_endpoints = ["http://127.0.0.1:8000/view?file=main.txt"]

    def mock_get(path, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "passwd" in path:
            resp.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
        elif "win.ini" in path:
            resp.text = "[fonts]\n[extensions]\n"
        else:
            resp.text = "Normal file content"
        return resp

    with patch.object(ws, "_get", side_effect=mock_get):
        findings = ws.path_traversal_test()

    assert len(findings) >= 1
    assert findings[0]["parameter"] == "file"
    assert "root:x:" in findings[0]["indicator"] or "[extensions]" in findings[0]["indicator"]


def test_waf_detect_and_bypass():
    ws = WebScanner("http://127.0.0.1:8000")

    def mock_get(path, **kwargs):
        resp = MagicMock()
        if "UNION SELECT" in path and "uNiOn" not in path:
            resp.status_code = 403
            resp.headers = {"cf-ray": "12345678"}
            resp.text = "error code: 1020 Cloudflare Ray ID"
        elif "uNiOn" in path:
            resp.status_code = 200
            resp.headers = {}
            resp.text = "ok"
        else:
            resp.status_code = 200
            resp.headers = {"cf-ray": "12345678"}
            resp.text = "cloudflare protected site"
        return resp

    with patch.object(ws, "_get", side_effect=mock_get):
        info = ws.waf_detect()
        assert info["detected"] is True
        assert info["vendor"] == "Cloudflare"

        bypasses = ws.waf_bypass_test()
        assert len(bypasses) >= 1
        assert any(b["technique"] == "Case Randomization" for b in bypasses)


def test_subdomain_takeover_detection():
    ws = WebScanner("https://example.com")
    ws.results["subdomains"] = ["blog.example.com"]

    def mock_urlopen(req, timeout=3.0, context=None):
        resp = MagicMock()
        resp.read.return_value = b"There isn't a GitHub Pages site here."
        return resp

    with patch("socket.getaddrinfo", return_value=[(None, None, None, "example.github.io")]), \
         patch("urllib.request.urlopen", side_effect=mock_urlopen):
        findings = ws.subdomain_takeover_test()

    assert len(findings) >= 1
    assert findings[0]["vulnerable"] is True
    assert findings[0]["platform"] == "GitHub Pages"


def test_to_scan_results_maps_new_features():
    ws = WebScanner("https://example.com")
    ws.results["cmdi"] = [{
        "url": "https://example.com/api?cmd=test",
        "parameter": "cmd",
        "type": "semicolon-arithmetic",
        "evidence": "cmdi_49 detected",
    }]
    ws.results["path_traversal"] = [{
        "url": "https://example.com/view?file=test",
        "parameter": "file",
        "technique": "linux-relative",
        "indicator": "root:x:",
    }]
    ws.results["waf_bypass"] = [{
        "technique": "Case Randomization",
        "test_path": "/?id=1",
        "status": 200,
        "bypassed": True,
    }]
    ws.results["subdomain_takeover"] = [{
        "subdomain": "blog.example.com",
        "cname": "example.github.io",
        "platform": "GitHub Pages",
        "vulnerable": True,
    }]

    scan_results = ws.to_scan_results()
    modules = {r.module for r in scan_results}

    assert "web-cmdi" in modules
    assert "web-path-traversal" in modules
    assert "web-waf-bypass" in modules
    assert "web-subdomain-takeover" in modules

    cmdi_res = next(r for r in scan_results if r.module == "web-cmdi")
    assert cmdi_res.severity == Severity.CRITICAL

    traversal_res = next(r for r in scan_results if r.module == "web-path-traversal")
    assert traversal_res.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_web_scan_async_with_focused_checks():
    def mock_get(self, path, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html><body>Home <a href='/page?id=1'>Link</a></body></html>"
        return resp

    with patch.object(WebScanner, "_get", mock_get):
        results = await web_scan_async(
            "http://127.0.0.1:8000",
            checks=["spider", "cmdi", "traversal", "waf", "takeover"],
        )
        assert isinstance(results, list)

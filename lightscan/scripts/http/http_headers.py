"""Grab and analyse HTTP response headers."""
import asyncio, ssl, urllib.request, urllib.error
SCRIPT_NAME  = "http_headers"
SCRIPT_PORTS = [80, 443, 8080, 8443, 8000, 3000]
SCRIPT_TAGS  = ["http", "safe", "discovery"]

from lightscan.core.engine import ScanResult, Severity

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    url    = f"{scheme}://{host}:{port}/"
    loop   = asyncio.get_running_loop()
    def _fetch():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "LightScan/2.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx if scheme=="https" else None) as r:
                return dict(r.info()), r.status
        except urllib.error.HTTPError as e:
            return dict(e.headers), e.code
        except Exception:
            return {}, 0
    headers, status = await loop.run_in_executor(None, _fetch)
    if not headers: return []
    results = []
    # Security header analysis
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if missing:
        results.append(ScanResult("script:http_headers", host, port, "missing_headers",
            Severity.MEDIUM,
            f"Missing security headers: {', '.join(missing[:3])}",
            {"missing": missing, "present": {k:v for k,v in headers.items() if k in SECURITY_HEADERS}}))
    # Server header disclosure
    server = headers.get("Server", "")
    if server:
        results.append(ScanResult("script:http_headers", host, port, "server_header",
            Severity.LOW, f"Server: {server}", {"server": server}))
    # Interesting headers
    for hdr in ["X-Powered-By", "X-AspNet-Version", "X-Generator"]:
        if hdr in headers:
            results.append(ScanResult("script:http_headers", host, port, "info_disclosure",
                Severity.LOW, f"{hdr}: {headers[hdr]}", {"header": hdr, "value": headers[hdr]}))
    return results

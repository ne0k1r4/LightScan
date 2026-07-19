"""Test which HTTP methods are allowed on the server."""
import asyncio, ssl
SCRIPT_NAME  = "http_methods"
SCRIPT_PORTS = [80, 443, 8080, 8443]
SCRIPT_TAGS  = ["http", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

DANGEROUS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_running_loop()
    allowed = []
    def _try(method):
        import urllib.request, urllib.error
        try:
            ctx = None
            if scheme == "https":
                import ssl; ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"{scheme}://{host}:{port}/",
                method=method, headers={"User-Agent": "LightScan/2.0"})
            with urllib.request.urlopen(req, timeout=3.0, **({"context":ctx} if ctx else {})) as r:
                return method, r.status
        except urllib.error.HTTPError as e:
            if e.code not in (405, 501): return method, e.code
        except Exception:
            pass
        return None
    results_raw = await asyncio.gather(*[
        loop.run_in_executor(None, _try, m)
        for m in ["GET","POST","PUT","DELETE","OPTIONS","TRACE","PATCH","HEAD"]
    ])
    allowed = [r[0] for r in results_raw if r]
    if not allowed: return []
    dangerous = [m for m in allowed if m in DANGEROUS]
    sev = Severity.HIGH if dangerous else Severity.INFO
    return [ScanResult("script:http_methods", host, port, "methods",
        sev, f"Allowed: {', '.join(allowed)}" + (f" | DANGEROUS: {', '.join(dangerous)}" if dangerous else ""),
        {"allowed": allowed, "dangerous": dangerous})]

"""Detect HTTP authentication mechanisms."""
import asyncio, ssl, urllib.request, urllib.error, base64
SCRIPT_NAME  = "http_auth_detect"
SCRIPT_PORTS = [80, 443, 8080, 8443, 8000, 8888]
SCRIPT_TAGS  = ["http", "auth", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_running_loop()

    def _probe(path="/"):
        try:
            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"User-Agent": "LightScan/2.0"}
            )
            kw = {"context": ctx} if ctx else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)
        except Exception:
            return 0, {}

    status, headers = await loop.run_in_executor(None, _probe)
    results = []
    if status == 0:
        return results

    www_auth = headers.get("Www-Authenticate", "")
    if www_auth:
        auth_type = www_auth.split()[0].upper() if www_auth else ""
        sev = Severity.MEDIUM
        detail = f"Auth required: {www_auth[:80]}"
        if "NTLM" in auth_type or "NEGOTIATE" in auth_type:
            sev = Severity.HIGH
            detail = f"Windows Auth (NTLM/Kerberos): {www_auth[:80]}"
        elif "BASIC" in auth_type:
            sev = Severity.HIGH
            detail = f"HTTP Basic Auth — credentials in plaintext: {www_auth[:80]}"
        results.append(ScanResult("script:http_auth_detect", host, port,
            "auth_required", sev, detail, {"auth": www_auth, "status": status}))
    elif status == 200:
        results.append(ScanResult("script:http_auth_detect", host, port,
            "no_auth", Severity.INFO, "No authentication required (HTTP 200)",
            {"status": 200}))
    return results

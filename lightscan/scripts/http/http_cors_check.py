"""Check for CORS misconfiguration."""
import asyncio, ssl, urllib.request, urllib.error
SCRIPT_NAME  = "http_cors_check"
SCRIPT_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000]
SCRIPT_TAGS  = ["http", "cors", "safe", "misconfig"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_running_loop()

    def _test():
        try:
            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}/",
                headers={
                    "User-Agent": "LightScan/2.0",
                    "Origin": "https://evil.com",
                }
            )
            kw = {"context": ctx} if ctx else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                headers = dict(r.headers)
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
        except Exception:
            return []

        results = []
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            results.append(("MEDIUM", "CORS wildcard (*) — any origin allowed",
                {"acao": acao, "acac": acac}))
        elif "evil.com" in acao:
            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
            results.append((sev,
                f"CORS reflects arbitrary origin{' + credentials' if acac.lower()=='true' else ''}",
                {"acao": acao, "acac": acac}))
        return results

    raw = await loop.run_in_executor(None, _test)
    out = []
    for sev_str, msg, extra in raw:
        sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "MEDIUM": Severity.MEDIUM}.get(sev_str, Severity.MEDIUM)
        out.append(ScanResult("script:http_cors_check", host, port,
            "cors_misconfig", sev, msg, extra))
    return out

"""Detect web technologies from headers and body."""
import asyncio, ssl, urllib.request, urllib.error, re
SCRIPT_NAME  = "http_tech_detect"
SCRIPT_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
SCRIPT_TAGS  = ["http", "safe", "discovery", "fingerprint"]
from lightscan.core.engine import ScanResult, Severity

TECH_SIGS = {
    "WordPress":    [re.compile(r"wp-content|wp-includes|WordPress", re.I)],
    "Drupal":       [re.compile(r"Drupal|sites/default|drupal\.js", re.I)],
    "Joomla":       [re.compile(r"Joomla|/components/com_", re.I)],
    "Laravel":      [re.compile(r"laravel_session|Laravel", re.I)],
    "Django":       [re.compile(r"csrfmiddlewaretoken|Django", re.I)],
    "React":        [re.compile(r"react-root|__REACT|ReactDOM", re.I)],
    "Angular":      [re.compile(r"ng-version|angular\.min\.js", re.I)],
    "Vue.js":       [re.compile(r"vue\.min\.js|__vue__", re.I)],
    "jQuery":       [re.compile(r"jquery[\-./]([0-9.]+)", re.I)],
    "Bootstrap":    [re.compile(r"bootstrap[\-./]([0-9.]+)", re.I)],
    "Spring Boot":  [re.compile(r"Spring Framework|Whitelabel Error|actuator", re.I)],
    "ASP.NET":      [re.compile(r"__VIEWSTATE|ASP\.NET|X-AspNet-Version", re.I)],
    "PHP":          [re.compile(r"X-Powered-By.*PHP|\.php", re.I)],
    "Node.js":      [re.compile(r"X-Powered-By.*Express|node\.js", re.I)],
    "Nginx":        [re.compile(r"nginx", re.I)],
    "Apache":       [re.compile(r"Apache", re.I)],
    "IIS":          [re.compile(r"Microsoft-IIS|X-Powered-By.*ASP", re.I)],
    "Tomcat":       [re.compile(r"Apache Tomcat|Coyote", re.I)],
    "Elasticsearch":[re.compile(r"elasticsearch|You Know, for Search", re.I)],
    "Jenkins":      [re.compile(r"Jenkins|X-Jenkins", re.I)],
}

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_running_loop()

    def _detect():
        try:
            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}/",
                headers={"User-Agent": "LightScan/2.0"}
            )
            kw = {"context": ctx} if ctx else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                body    = r.read(32768).decode("utf-8", "replace")
                headers = str(dict(r.headers))
        except urllib.error.HTTPError as e:
            try:
                body = e.read(8192).decode("utf-8", "replace")
            except Exception:
                body = ""
            headers = str(dict(e.headers))
        except Exception:
            return []

        combined = body + headers
        found = []
        for tech, patterns in TECH_SIGS.items():
            for pat in patterns:
                if pat.search(combined):
                    found.append(tech)
                    break
        return found

    techs = await loop.run_in_executor(None, _detect)
    if not techs:
        return []
    return [ScanResult("script:http_tech_detect", host, port, "tech_detected",
        Severity.INFO, f"Technologies: {', '.join(techs)}",
        {"technologies": techs})]

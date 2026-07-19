"""Extract TLS certificate info and check expiry."""
import asyncio, ssl, socket
from datetime import datetime
SCRIPT_NAME  = "tls_cert_info"
SCRIPT_PORTS = [443, 8443, 993, 995, 636, 465, 587, 6443]
SCRIPT_TAGS  = ["tls", "ssl", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    def _get_cert():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert    = ssock.getpeercert()
                    version = ssock.version()
                    cipher  = ssock.cipher()
                    return cert, version, cipher
        except Exception:
            return None, None, None
    cert, version, cipher = await loop.run_in_executor(None, _get_cert)
    if not cert: return []
    results = []
    # Expiry check
    exp_str = cert.get("notAfter","")
    if exp_str:
        try:
            exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.utcnow()).days
            sev = Severity.CRITICAL if days_left < 7 else Severity.HIGH if days_left < 30 else Severity.INFO
            results.append(ScanResult("script:tls_cert_info", host, port, "cert_expiry",
                sev, f"TLS cert expires in {days_left} days ({exp_str})",
                {"days_left": days_left, "expiry": exp_str, "version": version}))
        except Exception: pass
    # Weak TLS version
    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        results.append(ScanResult("script:tls_cert_info", host, port, "weak_tls",
            Severity.HIGH, f"Weak TLS version: {version}",
            {"version": version}))
    # Subject info
    subject = {}
    for field in cert.get("subject", []):
        for k, v in field: subject[k] = v
    cn = subject.get("commonName", "")
    if cn:
        results.append(ScanResult("script:tls_cert_info", host, port, "tls_cert",
            Severity.INFO, f"CN={cn} | {version} | {cipher[0] if cipher else ''}",
            {"cn": cn, "subject": subject, "version": version,
             "cipher": cipher[0] if cipher else ""}))
    return results

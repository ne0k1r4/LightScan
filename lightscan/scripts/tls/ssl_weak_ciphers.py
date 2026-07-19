"""Detect weak SSL/TLS ciphers and protocols."""
import asyncio, ssl, socket
SCRIPT_NAME  = "ssl_weak_ciphers"
SCRIPT_PORTS = [443, 8443, 993, 995, 465, 587, 636, 3389]
SCRIPT_TAGS  = ["tls", "ssl", "safe", "crypto"]
from lightscan.core.engine import ScanResult, Severity

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "ADH", "AECDH", "RC2", "IDEA",
]
WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    results = []

    def _check():
        findings = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    cipher = s.cipher()
                    proto  = s.version()
                    if cipher:
                        name = cipher[0]
                        for weak in WEAK_CIPHERS:
                            if weak.upper() in name.upper():
                                findings.append(("CRITICAL", f"Weak cipher in use: {name}"))
                                break
                        else:
                            findings.append(("INFO", f"Cipher: {name}"))
                    if proto in WEAK_PROTOCOLS:
                        findings.append(("HIGH", f"Weak protocol: {proto}"))
                    elif proto:
                        findings.append(("INFO", f"Protocol: {proto}"))
        except Exception:
            pass
        return findings

    raw = await loop.run_in_executor(None, _check)
    for sev_str, msg in raw:
        sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "MEDIUM": Severity.MEDIUM, "INFO": Severity.INFO}.get(sev_str, Severity.INFO)
        results.append(ScanResult("script:ssl_weak_ciphers", host, port,
            "weak_cipher" if sev_str != "INFO" else "cipher_info",
            sev, msg, {"detail": msg}))
    return results

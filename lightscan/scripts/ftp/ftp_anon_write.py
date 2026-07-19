"""Test FTP anonymous login and write access."""
import asyncio, ftplib, io
SCRIPT_NAME  = "ftp_anon_write"
SCRIPT_PORTS = [21, 2121]
SCRIPT_TAGS  = ["ftp", "safe", "auth", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()

    def _test():
        results = []
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            banner = ftp.getwelcome()
            try:
                ftp.login("anonymous", "lightscan@test.com")
                # Login succeeded — check write access
                try:
                    ftp.storbinary("STOR lightscan_test.txt", io.BytesIO(b"lightscan"))
                    ftp.delete("lightscan_test.txt")
                    results.append(("CRITICAL", "FTP anonymous login + WRITE access",
                        {"write": True, "banner": banner}))
                except ftplib.error_perm:
                    results.append(("HIGH", "FTP anonymous login (read-only)",
                        {"write": False, "banner": banner}))
            except ftplib.error_perm:
                results.append(("INFO", f"FTP banner: {banner[:80]}",
                    {"anonymous": False, "banner": banner}))
            ftp.quit()
        except Exception:
            pass
        return results

    raw = await loop.run_in_executor(None, _test)
    out = []
    for sev_str, msg, extra in raw:
        sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "INFO": Severity.INFO}.get(sev_str, Severity.INFO)
        out.append(ScanResult("script:ftp_anon_write", host, port,
            "ftp_anon", sev, msg, extra))
    return out

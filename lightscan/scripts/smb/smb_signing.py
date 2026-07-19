"""Check if SMB signing is required."""
import asyncio, socket, struct
SCRIPT_NAME  = "smb_signing"
SCRIPT_PORTS = [445, 139]
SCRIPT_TAGS  = ["smb", "windows", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    def _check():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            # SMB1 negotiate request
            pkt = (b"\x00\x00\x00\x54" + b"\xffSMB" + b"\x72"
                   + b"\x00" * 4 + b"\x08\x00" + b"\x00" * 6
                   + b"\xff\xff\xff\xff" + b"\x00" * 10
                   + b"\x00\x31" + b"\x00\x02NT LM 0.12\x00"
                   + b"\x02SMB 2.002\x00" + b"\x02SMB 2.???\x00")
            s.send(pkt)
            resp = s.recv(256)
            s.close()
            if len(resp) < 40:
                return None
            sec_mode = resp[39]
            signing_required = bool(sec_mode & 0x08)
            signing_enabled  = bool(sec_mode & 0x04)
            return signing_required, signing_enabled
        except Exception:
            return None
    result = await loop.run_in_executor(None, _check)
    if result is None:
        return []
    signing_required, signing_enabled = result
    if not signing_enabled:
        return [ScanResult("script:smb_signing", host, port, "smb_signing_disabled",
            Severity.HIGH, "SMB signing disabled — relay attacks possible",
            {"signing_required": False, "signing_enabled": False})]
    if signing_enabled and not signing_required:
        return [ScanResult("script:smb_signing", host, port, "smb_signing_not_required",
            Severity.MEDIUM, "SMB signing enabled but not required",
            {"signing_required": False, "signing_enabled": True})]
    return [ScanResult("script:smb_signing", host, port, "smb_signing_required",
        Severity.INFO, "SMB signing required",
        {"signing_required": True, "signing_enabled": True})]

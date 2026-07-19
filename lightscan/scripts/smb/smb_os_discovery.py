"""Enumerate OS and hostname via SMB negotiate."""
import asyncio, struct, socket
SCRIPT_NAME  = "smb_os_discovery"
SCRIPT_PORTS = [445, 139]
SCRIPT_TAGS  = ["smb", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

SMB_NEG = bytes([
    0x00,0x00,0x00,0x54,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,
    0x53,0xc8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xfe,
    0x00,0x00,0x00,0x00,0x00,0x31,0x00,0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,
    0x31,0x2e,0x30,0x00,0x02,0x4c,0x4d,0x31,0x2e,0x32,0x58,0x30,0x30,0x32,
    0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00,
])

async def run(host, port, timeout=8.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(SMB_NEG); await w.drain()
        resp = await asyncio.wait_for(r.read(1024), timeout=timeout)
        w.close()
        if len(resp) < 36: return []
        # Parse SMB response for OS string
        if resp[4:8] != b"\xff\x53\x4d\x42": return []
        os_info = resp[73:].decode("utf-16-le", errors="replace").rstrip("\x00")
        parts = [p.strip() for p in os_info.split("\x00") if p.strip()]
        os_str = " | ".join(parts[:3]) if parts else "Unknown"
        return [ScanResult("script:smb_os_discovery", host, port, "smb_os",
            Severity.INFO, f"SMB OS: {os_str}",
            {"os": os_str, "raw_parts": parts})]
    except Exception:
        return []

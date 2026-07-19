"""Test if DNS server allows open recursion."""
import asyncio, struct, socket, time
SCRIPT_NAME  = "dns_recursion"
SCRIPT_PORTS = [53]
SCRIPT_TAGS  = ["dns", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

def _build_dns_query(name):
    txid = int(time.time()) & 0xFFFF
    hdr  = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in name.split("."):
        enc = part.encode()
        qname += struct.pack("B", len(enc)) + enc
    return hdr + qname + b"\x00" + struct.pack("!HH", 1, 1)

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    def _test():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            # Query an external domain — if it resolves, recursion is open
            q = _build_dns_query("scanme.nmap.org")
            s.sendto(q, (host, port))
            resp, _ = s.recvfrom(512)
            s.close()
            ancount = struct.unpack("!H", resp[6:8])[0]
            return ancount > 0
        except Exception:
            return False
    is_open = await loop.run_in_executor(None, _test)
    if is_open:
        return [ScanResult("script:dns_recursion", host, port, "open_recursion",
            Severity.MEDIUM, "DNS server allows open recursion (can be abused for DRDoS)",
            {"recursive": True})]
    return [ScanResult("script:dns_recursion", host, port, "recursion_disabled",
        Severity.INFO, "DNS recursion disabled", {"recursive": False})]

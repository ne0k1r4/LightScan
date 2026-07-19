"""Extract SSH supported algorithms and flag weak ones."""
import asyncio, socket
SCRIPT_NAME  = "ssh_algorithms"
SCRIPT_PORTS = [22, 2222]
SCRIPT_TAGS  = ["ssh", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

WEAK_ALGOS = ["arcfour","blowfish","cast128","3des","des","md5","sha1","diffie-hellman-group1","diffie-hellman-group-exchange-sha1"]

async def run(host, port, timeout=8.0):
    loop = asyncio.get_running_loop()
    def _get_kex():
        import struct, socket
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            # Read banner
            banner = s.recv(256).decode("utf-8","replace").strip()
            # Send our banner
            s.send(b"SSH-2.0-LightScan_2.0_scanner\r\n")
            # Read KEX_INIT packet
            raw = b""
            while len(raw) < 4:
                raw += s.recv(4 - len(raw))
            pkt_len = struct.unpack("!I", raw[:4])[0]
            payload = b""
            while len(payload) < pkt_len:
                payload += s.recv(pkt_len - len(payload))
            s.close()
            # Parse KEX_INIT (skip padding and message type)
            pad_len = payload[0]
            msg = payload[1:]
            if msg[0] != 20: return banner, {}  # not KEXINIT
            # Skip cookie (16 bytes) + message type
            pos = 17
            lists = {}
            names = ["kex_algos","server_host_key_algos","enc_c2s","enc_s2c",
                     "mac_c2s","mac_s2c","comp_c2s","comp_s2c"]
            for name in names:
                if pos + 4 > len(msg): break
                slen = struct.unpack("!I", msg[pos:pos+4])[0]
                pos += 4
                if pos + slen > len(msg): break
                algos = msg[pos:pos+slen].decode("utf-8","replace").split(",")
                lists[name] = algos
                pos += slen
            return banner, lists
        except Exception:
            return "", {}
    banner, algos = await loop.run_in_executor(None, _get_kex)
    if not algos: return []
    results = []
    all_algos = []
    for v in algos.values(): all_algos.extend(v)
    weak = [a for a in all_algos if any(w in a.lower() for w in WEAK_ALGOS)]
    if weak:
        results.append(ScanResult("script:ssh_algorithms", host, port, "weak_algos",
            Severity.MEDIUM, f"Weak SSH algorithms: {', '.join(set(weak[:5]))}",
            {"weak": list(set(weak)), "all": algos}))
    results.append(ScanResult("script:ssh_algorithms", host, port, "ssh_kex",
        Severity.INFO,
        f"KEX: {', '.join(algos.get('kex_algos',['?'])[:3])}",
        {"algorithms": algos, "banner": banner}))
    return results

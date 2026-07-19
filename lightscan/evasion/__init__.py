"""LightScan v2.0 PHANTOM — Evasion Layer | Developer: Light"""
from __future__ import annotations

import asyncio
import random
import re
import struct
import time
from typing import Optional

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "curl/8.7.1", "python-httpx/0.27.0", "Go-http-client/1.1",
]

class Jitter:
    def __init__(self, lo=0.0, hi=0.0):
        self.lo = lo
        self.hi = hi

    async def sleep(self):
        if self.hi > 0:
            await asyncio.sleep(random.uniform(self.lo, self.hi))

    @classmethod
    def stealth(cls):
        return cls(2.0, 8.0)

    @classmethod
    def normal(cls):
        return cls(0.3, 1.5)

    @classmethod
    def off(cls):
        return cls(0.0, 0.0)

def random_ua():
    return random.choice(UA_POOL)

class SOCKS5:
    def __init__(self, host, port, user="", passwd=""):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd

    async def connect(self, dest_host, dest_port, timeout=10.0):
        r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=timeout)
        if self.user:
            w.write(b"\x05\x02\x00\x02")
        else:
            w.write(b"\x05\x01\x00")
        await w.drain()
        choice = await asyncio.wait_for(r.read(2), timeout=timeout)
        if len(choice) < 2 or choice[0] != 5:
            w.close()
            raise ConnectionError("SOCKS5 handshake failed")
        if choice[1] == 0x02:
            auth = (bytes([0x01, len(self.user)]) + self.user.encode() +
                    bytes([len(self.passwd)]) + self.passwd.encode())
            w.write(auth)
            await w.drain()
            ar = await asyncio.wait_for(r.read(2), timeout=timeout)
            if len(ar) < 2 or ar[1] != 0:
                w.close()
                raise ConnectionError("SOCKS5 auth failed")
        elif choice[1] != 0:
            w.close()
            raise ConnectionError(f"SOCKS5 auth method {choice[1]} unsupported")
        dest = dest_host.encode()
        w.write(b"\x05\x01\x00\x03" + bytes([len(dest)]) + dest + struct.pack("!H", dest_port))
        await w.drain()
        cr = await asyncio.wait_for(r.read(10), timeout=timeout)
        if len(cr) < 2 or cr[1] != 0:
            w.close()
            raise ConnectionError(f"SOCKS5 connect failed: {cr[1] if len(cr) > 1 else '?'}")
        return r, w

class ProxyChain:
    def __init__(self, proxies):
        self._p = [SOCKS5(p["host"], p["port"], p.get("user", ""), p.get("pass", "")) for p in proxies]
        self._i = 0

    def next(self):
        p = self._p[self._i % len(self._p)]
        self._i += 1
        return p

    def rand(self):
        return random.choice(self._p)

    async def connect(self, host, port, timeout=10.0):
        return await self.rand().connect(host, port, timeout)

    @staticmethod
    def from_file(path):
        proxies = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"(?:socks5://)?(?:([^:@]+):([^@]+)@)?([^:]+):(\d+)", line)
                if m:
                    proxies.append({
                        "user": m.group(1) or "",
                        "pass": m.group(2) or "",
                        "host": m.group(3),
                        "port": int(m.group(4))
                    })
        return ProxyChain(proxies)

# JA3/JA4 TLS Fingerprint Spoofing

CHROME_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:"
    "DHE-RSA-AES256-GCM-SHA384"
)

FIREFOX_CIPHERS = (
    "TLS_AES_128_GCM_SHA256:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384"
)

SAFARI_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305"
)

EDGE_CIPHERS = CHROME_CIPHERS

def get_spoofed_ssl_context(browser: str = "chrome") -> ssl.SSLContext:
    """
    Creates an SSLContext configured with browser-specific TLS ciphers
    and options to spoof JA3/JA4 fingerprints and bypass WAF detection.
    """
    import ssl
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Modern TLS standards
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Configure custom ciphers
    ciphers = {
        "chrome": CHROME_CIPHERS,
        "firefox": FIREFOX_CIPHERS,
        "safari": SAFARI_CIPHERS,
        "edge": EDGE_CIPHERS
    }.get(browser.lower(), CHROME_CIPHERS)
    
    try:
        context.set_ciphers(ciphers)
    except ssl.SSLError:
        try:
            context.set_ciphers("DEFAULT")
        except Exception:
            pass
            
    context.options |= ssl.OP_NO_COMPRESSION
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    return context

# Pair each browser UA with its corresponding JA3 context
UA_PROFILES = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36", "chrome"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36", "chrome"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0", "firefox"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", "safari"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0", "edge")
]

def get_evasion_client_profile() -> tuple[str, ssl.SSLContext]:
    """Returns a random User-Agent and a matching spoofed SSLContext."""
    ua, browser = random.choice(UA_PROFILES)
    return ua, get_spoofed_ssl_context(browser)

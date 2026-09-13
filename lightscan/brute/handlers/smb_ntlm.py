"""
LightScan v2.0 PHANTOM — Raw SMB/NTLMv2 Handler
Developer: Light

Direct integration of full SMB1 NTLM authentication:
  1. TCP connect to port 445
  2. SMB Negotiate (multi-dialect, extended security)
  3. Parse server's NTLMSSP challenge (8-byte nonce)
  4. Calculate NTLMv2 response (HMAC-MD5)
  5. SMB Session Setup with auth blob
  6. Parse response → success/failure/locked

Requires pycryptodome for HMAC-MD4 (pip install pycryptodome).
Falls back to Python stdlib hmac+hashlib if MD4 is available.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import socket
import struct
import time

log = logging.getLogger("lightscan.smb")

_SMB_NEG_CMD     = 0x72
_SMB_SESS_CMD    = 0x73
_NTLMSSP_NEG     = 0x01
_NTLMSSP_CHAL    = 0x02
_NTLMSSP_AUTH    = 0x03
_NTLM_FLAGS      = 0x00000001 | 0x00000002 | 0x00000200

_DIALECTS = (
    b'\x02PC NETWORK PROGRAM 1.0\x00'
    b'\x02MICROSOFT NETWORKS 1.03\x00'
    b'\x02MICROSOFT NETWORKS 3.0\x00'
    b'\x02LANMAN1.0\x00'
    b'\x02LM1.2X002\x00'
    b'\x02NT LM 0.12\x00'
    b'\x02SMB 2.002\x00'
)

class RawSMBAuth:
    def __init__(self, host: str, port: int = 445, timeout: float = 8.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.server_challenge: bytes | None = None
        self.uid = 0
        self._mid = 0

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            log.debug(f"SMB connect failed: {e}"); return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _send(self, smb_payload: bytes):
        netbios = struct.pack(">I", len(smb_payload))
        self.sock.sendall(netbios + smb_payload)

    def _recv(self) -> bytes | None:
        try:
            nb = self.sock.recv(4)
            if len(nb) < 4: return None
            plen = struct.unpack(">I", nb)[0]
            data = b""
            while len(data) < plen:
                chunk = self.sock.recv(min(4096, plen - len(data)))
                if not chunk: break
                data += chunk
            return data
        except (socket.timeout, OSError):
            return None

    def _smb_header(self, cmd: int, flags: int = 0x18, flags2: int = 0xC801,
                    tid: int = 0, uid: int = 0) -> bytes:
        self._mid += 1
        return (
            b'\xffSMB'
            + struct.pack('<B', cmd)
            + struct.pack('<I', 0)
            + struct.pack('<B', flags)
            + struct.pack('<H', flags2)
            + b'\x00' * 12
            + struct.pack('<H', uid)
            + struct.pack('<H', self._mid)
        )

    def negotiate(self) -> bool:
        body  = struct.pack('<B', 0)
        body += struct.pack('<H', len(_DIALECTS))
        body += _DIALECTS
        self._send(self._smb_header(_SMB_NEG_CMD) + body)
        resp = self._recv()
        if not resp or len(resp) < 36: return False
        if resp[:4] != b'\xffSMB': return False

        try:
            wc   = resp[32]
            blob_off = 32 + 1 + wc * 2 + 2
            if blob_off + 2 <= len(resp):
                blob_len = struct.unpack('<H', resp[blob_off:blob_off+2])[0]
                blob = resp[blob_off+2 : blob_off+2+blob_len]
                if blob.startswith(b'NTLMSSP\x00'):
                    self._parse_ntlm_challenge(blob)
        except Exception: pass

        return True

    def _parse_ntlm_challenge(self, blob: bytes):
        if len(blob) < 32: return
        msg_type = struct.unpack('<I', blob[8:12])[0]
        if msg_type == _NTLMSSP_CHAL:
            self.server_challenge = blob[24:32]
            log.debug(f"NTLM challenge: {self.server_challenge.hex()}")

    @staticmethod
    def _md4(data: bytes) -> bytes:
        try:
            return hashlib.new('md4', data).digest()
        except ValueError:
            try:
                from Crypto.Hash import MD4
                return MD4.new(data).digest()
            except ImportError:
                raise RuntimeError("MD4 unavailable: pip install pycryptodome")

    @staticmethod
    def _hmac_md5(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.md5).digest()

    def _ntlmv2_response(self, username: str, password: str,
                         domain: str, server_challenge: bytes) -> bytes:
        nt_hash = self._md4(password.encode('utf-16-le'))

        ntv2_hash = self._hmac_md5(
            nt_hash,
            (username.upper() + domain).encode('utf-16-le')
        )

        client_challenge = os.urandom(8)

        ts = int((time.time() + 11644473600) * 10_000_000)
        timestamp = struct.pack('<Q', ts)

        blob = (
            b'\x01\x01\x00\x00'
            + b'\x00\x00\x00\x00'
            + timestamp
            + client_challenge
            + b'\x00\x00\x00\x00'
            + b'\x00\x00\x00\x00'
        )

        ntv2_response = self._hmac_md5(ntv2_hash, server_challenge + blob) + blob
        return ntv2_response

    def session_setup(self, username: str, password: str, domain: str = '') -> str:
        """
        Returns: 'success' | 'failure' | 'locked' | 'error:<msg>'
        """
        if not self.server_challenge:
            return 'error:no_challenge'

        try:
            ntlm_resp = self._ntlmv2_response(username, password, domain, self.server_challenge)
        except Exception as e:
            return f'error:{e}'

        def sec_buf(data: bytes, base_offset: int) -> tuple[bytes, int]:
            hdr = struct.pack('<HHI', len(data), len(data), base_offset)
            return hdr, base_offset + len(data)

        domain_bytes = domain.encode('utf-16-le')
        user_bytes   = username.encode('utf-16-le')
        ws_bytes     = b''
        lm_bytes     = b'\x00' * 24

        base = 72
        lm_hdr,   base = sec_buf(lm_bytes,     base)
        ntlm_hdr, base = sec_buf(ntlm_resp,    base)
        dom_hdr,  base = sec_buf(domain_bytes, base)
        usr_hdr,  base = sec_buf(user_bytes,   base)
        ws_hdr,   base = sec_buf(ws_bytes,     base)

        auth_blob = (
            b'NTLMSSP\x00'
            + struct.pack('<I', _NTLMSSP_AUTH)
            + lm_hdr + ntlm_hdr + dom_hdr + usr_hdr + ws_hdr
            + struct.pack('<HHI', 0, 0, 0)
            + struct.pack('<I', _NTLM_FLAGS)
            + b'\x06\x01\x00\x00\x00\x00\x00\x0f'
            + lm_bytes + ntlm_resp + domain_bytes + user_bytes + ws_bytes
        )

        params = (
            struct.pack('<B', 0xFF)
            + struct.pack('<B', 0)
            + struct.pack('<H', 0)
            + struct.pack('<H', 0xFFFF)
            + struct.pack('<H', 2)
            + struct.pack('<H', 1)
            + struct.pack('<I', 0)
            + struct.pack('<H', len(auth_blob))
            + struct.pack('<I', 0)
            + struct.pack('<I', 0x80000054)
        )

        body  = struct.pack('<B', len(params) // 2)
        body += params
        body += struct.pack('<H', len(auth_blob) + 2)
        body += auth_blob
        body += b'\x00\x00'

        hdr = self._smb_header(_SMB_SESS_CMD, uid=self.uid)
        self._send(hdr + body)
        resp = self._recv()

        if not resp: return 'error:no_response'

        if len(resp) < 9: return 'error:short_response'
        ntstatus = struct.unpack('<I', resp[4:8])[0]

        if ntstatus == 0x00000000:   return 'success'
        if ntstatus == 0xC000006D:   return 'failure'
        if ntstatus == 0xC0000064:   return 'failure'
        if ntstatus == 0xC0000072:   return 'locked'
        if ntstatus == 0xC0000234:   return 'locked'
        if ntstatus == 0xC000006E:   return 'locked'
        return f'error:ntstatus=0x{ntstatus:08x}'

    def authenticate(self, username: str, password: str, domain: str = '') -> tuple[bool, str]:
        """Returns (success, message)"""
        if not self.connect():
            return False, 'connection_failed'
        try:
            if not self.negotiate():
                return False, 'negotiate_failed'

            if not self.server_challenge:
                neg_blob = (
                    b'NTLMSSP\x00'
                    + struct.pack('<I', _NTLMSSP_NEG)
                    + struct.pack('<I', _NTLM_FLAGS)
                    + b'\x00' * 16
                    + b'\x06\x01\x00\x00\x00\x00\x00\x0f'
                )
                params = (
                    struct.pack('<B', 0xFF) + struct.pack('<B',0) + struct.pack('<H',0)
                    + struct.pack('<H', 0xFFFF) + struct.pack('<H',2)
                    + struct.pack('<H',1) + struct.pack('<I',0)
                    + struct.pack('<H', len(neg_blob))
                    + struct.pack('<I',0) + struct.pack('<I',0)
                )
                body  = struct.pack('<B', len(params)//2) + params
                body += struct.pack('<H', len(neg_blob)+2) + neg_blob + b'\x00\x00'
                hdr   = self._smb_header(_SMB_SESS_CMD, uid=0)
                self._send(hdr + body)
                resp  = self._recv()
                if resp and len(resp) > 36:
                    try:
                        wc2 = resp[32]
                        boff = 32 + 1 + wc2 * 2 + 2
                        blen = struct.unpack('<H', resp[boff:boff+2])[0]
                        blob = resp[boff+2:boff+2+blen]
                        if blob.startswith(b'NTLMSSP\x00'):
                            self._parse_ntlm_challenge(blob)
                    except Exception:
                        pass

            if not self.server_challenge:
                return False, 'no_challenge_received'

            result = self.session_setup(username, password, domain)
            if result == 'success':   return True,  'SUCCESS'
            if result == 'locked':    return False, 'ACCOUNT_LOCKED'
            if result == 'failure':   return False, 'auth_failed'
            return False, result
        except Exception as e:
            return False, f'exception:{e}'
        finally:
            self.close()

def make_smb_ntlm_handler(host: str, port: int = 445, timeout: float = 8.0,
                          domain: str = '', **kw):
    """
    Returns an async (user, passwd) → (bool, str) handler for BruteEngine.
    Tries impacket first (most reliable), then falls back to RawSMBAuth.
    """
    try:
        from impacket.smbconnection import SMBConnection

        async def impacket_handler(user: str, passwd: str) -> tuple[bool, str]:
            def _try():
                try:
                    conn = SMBConnection(host, host, timeout=int(timeout))
                    conn.login(user, passwd, domain=domain)
                    conn.logoff()
                    return True, 'SUCCESS'
                except Exception as e:
                    msg = str(e).lower()
                    if 'locked' in msg:      return False, 'ACCOUNT_LOCKED'
                    if 'logon_failure' in msg or 'wrong' in msg: return False, 'auth_failed'
                    return False, str(e)
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _try)

        return impacket_handler

    except ImportError:
        pass

    async def raw_handler(user: str, passwd: str) -> tuple[bool, str]:
        def _try():
            auth = RawSMBAuth(host, port, timeout)
            return auth.authenticate(user, passwd, domain)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _try)

    return raw_handler

async def check_null_session(host: str, port: int = 445,
                              timeout: float = 5.0) -> dict:
    """try SMB null session and anonymous login before brute forcing.
    
    returns: {null_session, anonymous, shares, os, error}
    """
    result = {"null_session": False, "anonymous": False,
               "shares": [], "os": "", "error": ""}
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        result["error"] = "impacket not installed"; return result

    for username, key in [("", "null_session"), ("anonymous", "anonymous")]:
        conn = None
        try:
            conn = SMBConnection(host, host, timeout=int(timeout))
            result["os"] = conn.getServerOS() or ""
            conn.login(username, "")
            result[key] = True
            try:
                for s in conn.listShares():
                    result["shares"].append(s["shi1_netname"].rstrip("\x00"))
            except Exception: pass
            break
        except Exception as e:
            if "logon_failure" in str(e).lower() or "wrong password" in str(e).lower():
                continue
            result["error"] = str(e); break
        finally:
            if conn:
                try: conn.close()
                except Exception: pass
    return result

async def smb_precheck(host: str, port: int = 445, timeout: float = 5.0) -> list[str]:
    """run null/anonymous checks — call BEFORE brute force"""
    r = await check_null_session(host, port, timeout)
    out = []
    if r.get("error"): return []
    if r["null_session"]:
        out.append(f"[CRITICAL] null session on {host}:{port}")
        if r["shares"]: out.append(f"  shares: {', '.join(r['shares'])}")
    if r["anonymous"]:
        out.append(f"[HIGH] anonymous login on {host}:{port}")
    if not out:
        out.append(f"[INFO] null session denied on {host}:{port}" +
                   (f" | OS: {r['os']}" if r["os"] else ""))
    return out

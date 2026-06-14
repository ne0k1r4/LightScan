# scan/smb_enum.py — SMB enumeration: null session, share listing, RPC endpoints
# Light (Neok1ra)
# requires impacket
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from lightscan.core.engine import ScanResult, Severity

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, epm
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


@dataclass
class SMBInfo:
    host:          str
    os_version:    str  = ""
    domain:        str  = ""
    hostname:      str  = ""
    smb_version:   str  = ""
    signing:       bool = False
    null_session:  bool = False
    shares:        list = field(default_factory=list)
    rpc_endpoints: list = field(default_factory=list)
    errors:        list = field(default_factory=list)


_DIALECTS = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",   0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1",
}


def smb_enumerate(host: str, timeout: float = 5.0) -> SMBInfo:
    info = SMBInfo(host=host)
    if not HAS_IMPACKET:
        info.errors.append("impacket not installed")
        return info
    try:
        conn = SMBConnection(host, host, timeout=int(timeout))
        info.os_version  = conn.getServerOS() or ""
        info.domain      = conn.getServerDomain() or ""
        info.hostname    = conn.getServerName() or ""
        info.smb_version = _DIALECTS.get(conn.getDialect(), "SMB 1.x")
        info.signing     = bool(conn.isSigningRequired())

        # try null session
        try:
            conn.login("", "")
            info.null_session = True
            try:
                for s in conn.listShares():
                    info.shares.append({
                        "name":    s["shi1_netname"].rstrip("\x00"),
                        "comment": s["shi1_remark"].rstrip("\x00"),
                        "type":    {0:"DISK",1:"PRINT",3:"IPC"}.get(s["shi1_type"]&3,"OTHER"),
                    })
            except Exception: pass
        except Exception: pass

        try: conn.close()
        except Exception: pass

    except Exception as e:
        info.errors.append(str(e))
        # common: port closed, auth issues, SMBv1 only

    # RPC endpoint mapper
    try:
        rpc = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:{host}[135]")
        rpc.set_connect_timeout(3)
        dce = rpc.get_dce_rpc(); dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)
        for entry in epm.hept_lookup(None, dce=dce):
            try:
                ann = str(entry["Annotation"]).strip("\x00")
                if ann: info.rpc_endpoints.append(ann)
            except Exception: pass
        dce.disconnect()
    except Exception: pass

    return info


async def smb_enum_async(host: str, timeout: float = 5.0) -> list[ScanResult]:
    loop = asyncio.get_running_loop()
    info = await loop.run_in_executor(None, smb_enumerate, host, timeout)
    results = []
    if info.errors and not info.os_version:
        return results

    detail = f"SMB {info.smb_version}"
    if info.os_version:  detail += f" | {info.os_version}"
    if info.domain:      detail += f" | domain={info.domain}"
    if not info.signing: detail += " | SIGNING=DISABLED"
    results.append(ScanResult("smb-enum", host, 445, "SMB",
        Severity.HIGH if not info.signing else Severity.INFO, detail))

    if info.null_session:
        results.append(ScanResult("smb-enum", host, 445, "SMB-NullSession",
            Severity.CRITICAL, f"null session allowed — {len(info.shares)} shares visible"))
        for s in info.shares:
            results.append(ScanResult("smb-enum", host, 445, "SMB-Share",
                Severity.HIGH, f"{s['name']} [{s['type']}] {s['comment']}".strip()))

    if info.rpc_endpoints:
        results.append(ScanResult("smb-enum", host, 135, "RPC",
            Severity.INFO, f"{len(info.rpc_endpoints)} endpoints: " +
            ", ".join(info.rpc_endpoints[:5])))
    return results

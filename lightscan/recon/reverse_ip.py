"""Reverse IP / virtual host discovery via PTR, Host header probing, and TLS SAN extraction."""
from __future__ import annotations

import asyncio
import socket
import ssl

from lightscan.core.models import Confidence, ScanResult, Severity

VHOST_PREFIXES = [
    "www", "admin", "dev", "staging", "test", "api", "mail", "webmail",
    "portal", "app", "cdn", "static", "blog", "shop", "store", "intranet",
    "vpn", "remote",
]


def _resolve_ip(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def _ptr_lookup(ip: str) -> list[str]:
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        names = [hostname] + list(aliases)
        return [n for n in names if n]
    except Exception:
        return []


def _extract_san(ip: str, timeout: float) -> list[str]:
    names: list[str] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        return names
                    return names
                for entry_type, entry_value in cert.get("subjectAltName", []):
                    if entry_type.lower() == "dns":
                        names.append(entry_value)
                subject = cert.get("subject", ())
                for rdn in subject:
                    for attr_type, attr_value in rdn:
                        if attr_type == "commonName" and attr_value not in names:
                            names.append(attr_value)
    except Exception:
        pass
    return names


def _default_response(ip: str, port: int, timeout: float) -> tuple[int, int]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 32768:
                    break
            first_line = resp.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            parts = first_line.split(None, 2)
            status = int(parts[1]) if len(parts) >= 2 else 0
            return status, len(resp)
    except Exception:
        return 0, 0


def _probe_vhost(
    ip: str,
    hostname: str,
    port: int,
    timeout: float,
    default_status: int,
    default_length: int,
) -> str | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            req = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 32768:
                    break
            first_line = resp.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            parts = first_line.split(None, 2)
            status = int(parts[1]) if len(parts) >= 2 else 0
            length = len(resp)
            if status != default_status:
                return hostname
            if default_length > 0 and abs(length - default_length) > max(100, default_length * 0.1):
                return hostname
    except Exception:
        pass
    return None


def _blocking_reverse_ip(target: str, timeout: float) -> list[dict]:
    ip = _resolve_ip(target)
    findings: list[dict] = []
    seen: set[str] = set()

    ptr_names = _ptr_lookup(ip)
    for name in ptr_names:
        lower = name.lower().rstrip(".")
        if lower not in seen:
            seen.add(lower)
            findings.append({"hostname": lower, "method": "PTR"})

    san_names = _extract_san(ip, timeout)
    for name in san_names:
        lower = name.lower().rstrip(".")
        if lower not in seen and not lower.startswith("*"):
            seen.add(lower)
            findings.append({"hostname": lower, "method": "TLS-SAN"})

    base_domain = ""
    for name in ptr_names + san_names:
        parts = name.rstrip(".").split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
            break

    if not base_domain and "." in target:
        parts = target.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])

    if base_domain:
        default_status, default_length = _default_response(ip, 80, timeout)
        for prefix in VHOST_PREFIXES:
            vhost = f"{prefix}.{base_domain}"
            if vhost.lower() in seen:
                continue
            result = _probe_vhost(ip, vhost, 80, timeout, default_status, default_length)
            if result:
                lower = result.lower()
                if lower not in seen:
                    seen.add(lower)
                    findings.append({"hostname": lower, "method": "vhost-probe"})

    return findings


async def reverse_ip_async(
    target: str,
    timeout: float = 10.0,
) -> list[ScanResult]:
    """Discover virtual hosts and domains sharing the same IP address."""
    results: list[ScanResult] = []
    try:
        findings = await asyncio.to_thread(_blocking_reverse_ip, target, timeout)
    except Exception:
        return results

    for finding in findings:
        results.append(ScanResult(
            module="recon-vhost",
            target=target,
            port=0,
            status="discovered",
            severity=Severity.INFO,
            detail=f"Virtual host discovered: {finding['hostname']} (via {finding['method']})",
            data=finding,
            confidence=Confidence.FIRM,
        ))

    return results

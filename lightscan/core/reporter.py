"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations

import csv
import html
import ipaddress
import json
import os
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from xml.dom import minidom

from lightscan.core.engine import ScanResult, Severity

class Reporter:

    stdout_override = None

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir

    def save(
        self,
        results: list[ScanResult],
        meta: dict,
        basename: str = "lightscan_report",
        fmt: str = "json",
    ) -> str:
        if self.output_dir == "-":
            return self._write_to_stdout(results, meta, fmt)

        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        timestamp = int(time.time())
        extension = {
            "json": "json",
            "nmap-xml": "xml",
            "html": "html",
            "csv": "csv",
            "minimal": "txt",
        }.get(fmt, "json")
        path = os.path.join(self.output_dir, f"{basename}_{timestamp}.{extension}")
        self._write_file(path, results, meta, fmt)
        print(f"[+] Report ({fmt}): {path}")
        return path

    def _write_to_stdout(self, results: list[ScanResult], meta: dict, fmt: str) -> str:
        import sys
        import tempfile

        extension = {
            "json": "json",
            "nmap-xml": "xml",
            "html": "html",
            "csv": "csv",
            "minimal": "txt",
        }.get(fmt, "json")
        descriptor, temporary_path = tempfile.mkstemp(suffix=f".{extension}")
        os.close(descriptor)
        try:
            self._write_file(temporary_path, results, meta, fmt)
            output = self.stdout_override or sys.__stdout__
            with open(temporary_path, encoding="utf-8", errors="replace") as handle:
                output.write(handle.read())
                output.flush()
        finally:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
        return "-"

    def _write_file(self, path: str, results: list[ScanResult], meta: dict, fmt: str) -> None:
        writers = {
            "json": self._write_json,
            "nmap-xml": self._write_nmap_xml,
            "html": self._write_html,
            "csv": self._write_csv,
            "minimal": self._write_minimal,
        }
        writers.get(fmt, self._write_json)(path, results, meta)

    def _write_json(self, path: str, results: list[ScanResult], meta: dict) -> None:
        document = {
            "meta": meta,
            "results": [self._json_result(result) for result in results],
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")

    @staticmethod
    def _json_result(result: ScanResult) -> dict:
        payload = result.to_dict()
        payload["host"] = result.target
        payload["service"] = result.data.get("service", result.module)
        return payload

    def _write_nmap_xml(self, path: str, results: list[ScanResult], meta: dict) -> None:
        start = int(meta.get("timestamp", meta.get("start", time.time())))
        root = ET.Element(
            "nmaprun",
            {
                "scanner": "lightscan",
                "args": str(meta.get("command", "")),
                "start": str(start),
                "startstr": time.ctime(start),
                "version": "2.6.0",
                "xmloutputversion": "1.04",
            },
        )
        ET.SubElement(
            root,
            "scaninfo",
            {"type": "connect", "protocol": "tcp", "numservices": "0", "services": ""},
        )
        ET.SubElement(root, "verbose", {"level": "0"})
        ET.SubElement(root, "debugging", {"level": "0"})

        by_host: dict[str, list[ScanResult]] = defaultdict(list)
        for result in results:
            by_host[result.target].append(result)

        for host, host_results in sorted(by_host.items()):
            host_node = ET.SubElement(root, "host")
            ET.SubElement(host_node, "status", {"state": "up", "reason": "user-set"})
            address, address_type = self._address_attributes(host)
            ET.SubElement(host_node, "address", {"addr": address, "addrtype": address_type})
            ports_node = ET.SubElement(host_node, "ports")

            port_results: dict[int, list[ScanResult]] = defaultdict(list)
            host_findings: list[ScanResult] = []
            for result in host_results:
                if result.port > 0:
                    port_results[result.port].append(result)
                else:
                    host_findings.append(result)

            for port, findings in sorted(port_results.items()):
                port_node = ET.SubElement(
                    ports_node,
                    "port",
                    {"protocol": "tcp", "portid": str(port)},
                )
                state = self._port_state(findings)
                ET.SubElement(port_node, "state", {"state": state, "reason": "syn-ack" if state == "open" else "unknown"})

                service = self._service_result(findings)
                if service:
                    attributes = self._service_attributes(service)
                    if attributes:
                        ET.SubElement(port_node, "service", attributes)

                for finding in findings:
                    if finding is service or finding.module in {"portscan", "service-version"}:
                        continue
                    self._append_script(port_node, finding)

            for finding in host_findings:
                self._append_script(host_node, finding)

        end = int(time.time())
        ET.SubElement(
            root,
            "runstats",
        )
        runstats = root[-1]
        ET.SubElement(
            runstats,
            "finished",
            {
                "time": str(end),
                "timestr": time.ctime(end),
                "elapsed": f"{max(0.0, end - start):.2f}",
                "summary": f"LightScan completed: {len(by_host)} host(s) scanned",
                "exit": "success",
            },
        )
        ET.SubElement(
            runstats,
            "hosts",
            {"up": str(len(by_host)), "down": "0", "total": str(len(by_host))},
        )

        pretty = minidom.parseString(ET.tostring(root, encoding="utf-8")).toprettyxml(indent="  ")
        pretty = "\n".join(line for line in pretty.splitlines() if line.strip())
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(f"{pretty}\n")

    @staticmethod
    def _address_attributes(host: str) -> tuple[str, str]:
        try:
            address = ipaddress.ip_address(host)
            return str(address), "ipv6" if address.version == 6 else "ipv4"
        except ValueError:
            return host, "ipv4"

    @staticmethod
    def _port_state(findings: list[ScanResult]) -> str:
        statuses = {finding.status for finding in findings}
        if "open" in statuses:
            return "open"
        if "open|filtered" in statuses:
            return "open|filtered"
        if "closed" in statuses:
            return "closed"
        return "unknown"

    @staticmethod
    def _service_result(findings: list[ScanResult]) -> ScanResult | None:
        for finding in findings:
            if finding.module == "service-version":
                return finding
        for finding in findings:
            if finding.module == "portscan":
                return finding
        return None

    @staticmethod
    def _service_attributes(result: ScanResult) -> dict[str, str]:
        data = result.data or {}
        service = str(data.get("service", "")).strip()
        if not service:
            service = result.detail.split("|", 1)[0].strip().split(" ", 1)[0]
        if not service:
            return {}

        attributes = {
            "name": service.lower(),
            "method": str(data.get("method", "probed" if result.module == "service-version" else "table")),
            "conf": str(data.get("confidence", 10 if result.module == "service-version" else 3)),
        }
        product = str(data.get("product", "")).strip()
        version = str(data.get("version", "")).strip()
        if product:
            attributes["product"] = product
        if version:
            attributes["version"] = version
        return attributes

    @staticmethod
    def _append_script(parent: ET.Element, finding: ScanResult) -> None:
        ET.SubElement(
            parent,
            "script",
            {
                "id": finding.module,
                "output": f"{finding.severity.value}: {finding.detail}",
            },
        )

    def _write_html(self, path: str, results: list[ScanResult], meta: dict) -> None:
        critical = sum(result.severity == Severity.CRITICAL for result in results)
        high = sum(result.severity == Severity.HIGH for result in results)
        medium = sum(result.severity == Severity.MEDIUM for result in results)
        row_list = []
        for result in results:
            conf_val = result.confidence.value if hasattr(result.confidence, 'value') else str(result.confidence)
            rem_html = f"<div class='rem'><strong>Fix:</strong> {html.escape(result.remediation)}</div>" if result.remediation else ""
            row_list.append(
                f"<tr class='{html.escape(result.severity.value.lower())}'>"
                f"<td><code>{html.escape(result.target)}</code></td>"
                f"<td>{result.port}</td>"
                f"<td><strong>{html.escape(result.module)}</strong></td>"
                f"<td><span class='s {html.escape(result.severity.value.lower())}'>{html.escape(result.severity.value)}</span></td>"
                f"<td><span class='c {html.escape(conf_val.lower())}'>{html.escape(conf_val)}</span></td>"
                f"<td><span class='tax-tag'>{html.escape(result.owasp or '')}</span><br><small class='tax-cwe'>{html.escape(result.cwe or '')}</small></td>"
                f"<td>{html.escape(result.detail)}{rem_html}</td>"
                f"</tr>"
            )
        rows = "\n".join(row_list)
        document = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>LightScan Security Assessment Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem;line-height:1.5}}
h1{{color:#f0f6fc;margin-bottom:0.25rem}}
.sub{{color:#8b949e;margin-top:0;font-size:0.9rem}}
table{{width:100%;border-collapse:collapse;margin-top:1.5rem;font-size:0.9rem}}
th{{background:#161b22;color:#f0f6fc;padding:10px;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:10px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover{{background:#161b22}}
code{{font-family:monospace;background:#161b22;padding:2px 6px;border-radius:4px;color:#79c0ff}}
.s{{padding:3px 8px;border-radius:12px;font-size:11px;font-weight:600;display:inline-block}}
.s.critical{{background:#490202;color:#ff7b72;border:1px solid #b62324}}
.s.high{{background:#3d1a00;color:#ffa657;border:1px solid #9e4a06}}
.s.medium{{background:#2e2405;color:#e3b341;border:1px solid #7d5b0a}}
.s.low{{background:#0d2d14;color:#7ee787;border:1px solid #196c2e}}
.s.info{{background:#161b22;color:#8b949e;border:1px solid #30363d}}
.c{{padding:2px 6px;border-radius:4px;font-size:10px;font-weight:600}}
.c.certain{{background:#1b472e;color:#7ee787}}
.c.firm{{background:#3e3012;color:#e3b341}}
.c.tentative{{background:#21262d;color:#8b949e}}
.tax-tag{{color:#58a6ff;font-weight:600;font-size:11px}}
.tax-cwe{{color:#8b949e;font-size:11px}}
.rem{{margin-top:6px;padding:6px 10px;background:#161b22;border-left:3px solid #1f6feb;border-radius:3px;font-size:12px;color:#a5d6ff}}
.stats{{display:flex;gap:1.5rem;margin:1.5rem 0}}
.stat{{background:#161b22;padding:1rem 1.5rem;border-radius:6px;border-top:3px solid #30363d}}
.stat.crit{{border-color:#ff7b72}}
.stat.hi{{border-color:#ffa657}}
.stat.med{{border-color:#e3b341}}
.stat h2{{margin:0;font-size:1.8rem;color:#f0f6fc}}
.stat p{{margin:0;color:#8b949e;font-size:0.85rem;text-transform:uppercase;letter-spacing:0.5px}}
</style></head><body>
<h1>LightScan Security Assessment Report</h1>
<p class='sub'>Generated {html.escape(time.ctime())} · LightScan v2.6.0</p>
<div class='stats'>
<div class='stat'><h2>{len(results)}</h2><p>Total Findings</p></div>
<div class='stat crit'><h2>{critical}</h2><p>Critical</p></div>
<div class='stat hi'><h2>{high}</h2><p>High</p></div>
<div class='stat med'><h2>{medium}</h2><p>Medium</p></div>
</div>
<table><tr><th>Host</th><th>Port</th><th>Vulnerability / Check</th><th>Severity</th><th>Confidence</th><th>OWASP & CWE</th><th>Evidence & Remediation</th></tr>
{rows}</table></body></html>"""
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(document)

    def _write_csv(self, path: str, results: list[ScanResult], meta: dict | None = None) -> None:
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["host", "port", "status", "service", "severity", "confidence", "owasp", "cwe", "remediation", "detail", "module"])
            for result in results:
                writer.writerow(
                    [
                        result.target,
                        result.port,
                        result.status,
                        result.data.get("service", result.module),
                        result.severity.value,
                        result.confidence.value if hasattr(result.confidence, 'value') else str(result.confidence),
                        result.owasp,
                        result.cwe,
                        result.remediation,
                        result.detail,
                        result.module,
                    ]
                )

    def _write_minimal(self, path: str, results: list[ScanResult], meta: dict | None = None) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            for result in sorted(results, key=lambda item: (item.target, item.port)):
                if result.port > 0:
                    handle.write(f"{result.target}:{result.port}\n")

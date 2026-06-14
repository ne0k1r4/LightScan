# core/reporter.py — multi-format report output
# Light (Neok1ra)
#
# formats: json (default), nmap-xml, html, csv, minimal
# added nmap-xml because every tool expects it and i was tired of converting
from __future__ import annotations
import csv, json, os, time
import xml.etree.ElementTree as ET
from xml.dom import minidom
from lightscan.core.engine import ScanResult, Severity


class Reporter:
    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir

    def save(self, results: list[ScanResult], meta: dict,
             basename: str = "lightscan_report", fmt: str = "json") -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        ts  = int(time.time())
        ext = {"json": "json", "nmap-xml": "xml", "html": "html",
               "csv": "csv", "minimal": "txt"}.get(fmt, "json")
        path = os.path.join(self.output_dir, f"{basename}_{ts}.{ext}")
        dispatch = {
            "json":     self._write_json,
            "nmap-xml": self._write_nmap_xml,
            "html":     self._write_html,
            "csv":      self._write_csv,
            "minimal":  self._write_minimal,
        }
        dispatch.get(fmt, self._write_json)(path, results, meta)
        print(f"[+] Report ({fmt}): {path}")
        return path

    def _write_json(self, path, results, meta):
        with open(path, "w") as f:
            json.dump({"meta": meta, "results": [
                {"host": r.host, "port": r.port, "service": r.service,
                 "severity": r.severity.value, "detail": r.detail, "module": r.module}
                for r in results]}, f, indent=2)

    def _write_nmap_xml(self, path, results, meta):
        """nmap-compatible XML — metasploit db_import + crackmapexec accept this"""
        by_host: dict[str, list] = {}
        for r in results:
            by_host.setdefault(r.host, []).append(r)

        root = ET.Element("nmaprun")
        root.set("scanner", "lightscan")
        root.set("version", "2.0.0-PHANTOM")
        root.set("start",   str(int(meta.get("start", time.time()))))
        root.set("xmloutputversion", "1.04")
        ET.SubElement(root, "scaninfo").set("type", "connect")

        for ip, host_results in by_host.items():
            h = ET.SubElement(root, "host")
            ET.SubElement(h, "status").set("state", "up")
            addr = ET.SubElement(h, "address")
            addr.set("addr", ip); addr.set("addrtype", "ipv4")
            ports_el = ET.SubElement(h, "ports")
            for r in host_results:
                p = ET.SubElement(ports_el, "port")
                p.set("protocol", "tcp"); p.set("portid", str(r.port))
                ET.SubElement(p, "state").set("state", "open")
                svc = ET.SubElement(p, "service")
                svc.set("name", r.service.lower())
                parts = r.detail.split("|")
                svc.set("product", parts[0].strip())
                if len(parts) > 1: svc.set("version", parts[1].strip())
                if r.severity.value in ("HIGH", "CRITICAL"):
                    sc = ET.SubElement(p, "script")
                    sc.set("id", "lightscan-severity")
                    sc.set("output", f"{r.severity.value}: {r.detail}")

        # minidom adds <?xml?> declaration — strip extra blank line it adds
        pretty = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        pretty = "
".join(l for l in pretty.splitlines() if l.strip())
        with open(path, "w") as f:
            f.write(pretty)

    def _write_html(self, path, results, meta):
        crit = sum(1 for r in results if r.severity == Severity.CRITICAL)
        high   = sum(1 for r in results if r.severity == Severity.HIGH)
        medium = sum(1 for r in results if r.severity == Severity.MEDIUM)
        rows = "\n".join(
            f"<tr class='{r.severity.value.lower()}'>"
            f"<td>{r.host}</td><td>{r.port}</td><td>{r.service}</td>"
            f"<td><span class='s {r.severity.value.lower()}'>{r.severity.value}</span></td>"
            f"<td>{r.detail}</td></tr>"
            for r in results)
        html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>LightScan Report</title>
<style>body{{font-family:monospace;background:#0d0d0d;color:#ccc;padding:2rem}}
h1{{color:#e84545}}table{{width:100%;border-collapse:collapse}}
th{{background:#1a1a1a;color:#e84545;padding:8px;text-align:left}}
td{{padding:6px 8px;border-bottom:1px solid #222}}tr:hover{{background:#151515}}
.critical td,.high td{{color:#ff6644}}.s{{padding:2px 8px;border-radius:3px;font-size:11px}}
.s.critical{{background:#3d0000;color:#ff4444}}.s.high{{background:#3d1a00;color:#ff8800}}
.stats{{display:flex;gap:2rem;margin:1rem 0}}
.stat{{background:#1a1a1a;padding:1rem;border-left:3px solid #e84545}}
.stat h2{{margin:0;color:#e84545}}.stat p{{margin:0;color:#888}}</style></head><body>
<h1>LightScan Report</h1>
<p style='color:#555'>generated {time.ctime()} · lightscan v2.0.0-PHANTOM</p>
<div class='stats'>
<div class='stat'><h2>{len(results)}</h2><p>findings</p></div>
<div class='stat'><h2>{crit}</h2><p>critical</p></div>
<div class='stat'><h2>{high}</h2><p>high</p></div></div>
<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Severity</th><th>Detail</th></tr>
{rows}</table></body></html>"""
        with open(path, "w") as f:
            f.write(html)

    def _write_csv(self, path: str, results: list, meta: dict | None = None):
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["host","port","service","severity","detail","module"])
            for r in results:
                w.writerow([r.host,r.port,r.service,r.severity.value,r.detail,r.module])

    def _write_minimal(self, path, results, meta=None):
        with open(path, "w") as f:
            for r in sorted(results, key=lambda x: (x.host, x.port)):
                f.write(f"{r.host}:{r.port}\n")

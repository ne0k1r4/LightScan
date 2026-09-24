"""
LightScan v2.6 — CLI Entry Point
Developer: Light (Neok1ra)

Usage:
  lightscan --scan -t 192.168.1.0/24 -p top100 --max-rate 250 --sv
  lightscan --scan --go-engine -t file:approved-targets.txt -p 22,80,443
  lightscan --dns target.com
  lightscan --cve -t 10.0.0.1 --scan
  lightscan --oauth https://login.target.com/oauth/authorize --oauth-client CLIENT_ID
  lightscan --diff old.json new.json
"""
from __future__ import annotations
import asyncio
import json
import sys
import time

from lightscan.banner import print_banner
from lightscan.core.engine import PhantomEngine, ScanResult, Severity
from lightscan.core.target import (
    DEFAULT_MAX_TARGETS,
    TargetSpecError,
    parse_ports,
    parse_targets,
    resolve,
)
from lightscan.core.checkpoint import Checkpoint
from lightscan.core.reporter import Reporter
from lightscan.scan.evasion import parse_timing
from lightscan.commands.parser import build_parser, normalize_command_argv
from lightscan.commands.help import print_minimal_help


def _targets(args) -> list[str]:
    """Expand the CLI target input once per scan stage with an explicit ceiling."""
    return parse_targets(args.target, max_targets=args.max_targets)

def parse_userlist(spec):
    if not spec:
        return ["admin","root","administrator","user","test","guest","service","operator"]
    if spec.startswith("file:"):
        with open(spec[5:]) as f: return [l.strip() for l in f if l.strip()]
    return [u.strip() for u in spec.split(",")]

def parse_passwdlist(spec, users=None, target_info=None, mutate=False):
    from lightscan.brute.mutation import MutationEngine, COMMON_PASSWORDS
    if not spec: return list(COMMON_PASSWORDS)
    if spec.lower()=="common": base=list(COMMON_PASSWORDS)
    elif spec.startswith("file:"): base=MutationEngine.load_wordlist(spec[5:])
    else: base=[p.strip() for p in spec.split(",")]
    if mutate:
        eng=MutationEngine(base_words=base,target_info=target_info or {})
        expanded=[]
        for u in (users or [""]): expanded.extend(eng.generate(username=u))
        return list(dict.fromkeys(expanded))
    return base

async def async_main(args):
    scan_modes = [
        args.scan,
        args.syn,
        getattr(args, 'syn_c', False),
        getattr(args, 'raw', False),
        getattr(args, 'packet_scan', False),
        getattr(args, 'stealth_scan', False),
    ]
    if sum(bool(m) for m in scan_modes) > 1:
        print("\033[38;5;208m[!] Multiple scan modes active — pick one: "
              "--scan / --syn / --raw / --packet-scan / --stealth-scan\033[0m")
        sys.exit(1)

    if (args.syn or getattr(args, 'raw', False) or
            getattr(args, 'packet_scan', False) or
            getattr(args, 'stealth_scan', False)):
        try:
            import os as _os
            if _os.geteuid() != 0:
                print("\033[38;5;208m[!] Raw/SYN scans require root. "
                      "Re-run with sudo or use --scan for connect-scan.\033[0m")
                sys.exit(1)
        except AttributeError:
            pass

    if getattr(args, 'brute', None) and not args.target:
        print("\033[38;5;208m[!] --brute requires -t / --target\033[0m")
        sys.exit(1)

    if getattr(args, "stream_open", None) and (
        getattr(args, "sv", False)
        or getattr(args, "lua_script", None)
        or getattr(args, "lua_script_tags", None)
    ):
        print("\033[38;5;208m[!] --stream-open is a retention-free discovery mode and cannot be "
              "combined with --sv or Lua checks. Run enrichment as a separate, reviewed pass.\033[0m")
        sys.exit(1)
    if getattr(args, "lua_concurrency", 1) < 1:
        print("\033[38;5;208m[!] --lua-concurrency must be at least 1.\033[0m")
        sys.exit(1)

    if any(value < 0 for value in (
        getattr(args, "max_rate", 0.0),
        getattr(args, "retries", 0),
        getattr(args, "retry_jitter", 0.0),
        getattr(args, "host_timeout", 0.0),
    )) or not 0.0 <= getattr(args, "retry_jitter", 0.0) <= 1.0 or any(value < 1 for value in (
        getattr(args, "per_host_concurrency", 1),
        getattr(args, "host_group_size", 1),
    )):
        print("\033[38;5;208m[!] Invalid streaming scan controls. "
              "Rate, retries, and host timeout cannot be negative; retry jitter must be 0.0 to 1.0; "
              "concurrency controls must be at least 1.\033[0m")
        sys.exit(1)

    if getattr(args, 'brute', None):
        from lightscan.brute.handlers import PROTOCOLS
        proto = args.brute.lower()
        if proto not in PROTOCOLS:
            print(f"\033[38;5;208m[!] Unknown brute protocol: {proto!r}\033[0m")
            print(f"    Available: {', '.join(sorted(PROTOCOLS))}\033[0m")
            sys.exit(1)

    timing_raw = getattr(args, 'timing', 'T4')
    try:
        parse_timing(timing_raw)
    except (ValueError, KeyError):
        print(f"\033[38;5;208m[!] Invalid timing: {timing_raw!r} — use T0..T5\033[0m")
        sys.exit(1)

    if not getattr(args, 'no_banner', False):
        print_banner()
    t_start=time.time(); all_results=[]; open_ports={}
    _target = args.target or getattr(args, 'web_scan', None) or ""
    meta={"target":_target,"timestamp":t_start,"duration":0,"command":" ".join(sys.argv)}

    cp=Checkpoint()
    if args.clear_checkpoint: cp.clear()
    if args.target: cp.set_target(args.target)

    try:
        return await _run_main_body(args, cp, t_start, all_results, open_ports, meta)
    finally:
        cp.flush()

async def run_search(query: str):
    print(f"\033[38;5;196m[SEARCH]\033[0m Searching scripts and templates for: \033[38;5;220m{query!r}\033[0m\n")
    
    from lightscan.cve.template_engine import TemplateLibrary
    from pathlib import Path
    dirs = [str(Path(__file__).parent / "templates")]
    lib = TemplateLibrary(dirs)
    matching_templates = lib.search(query)
    
    from lightscan.scan.scripts import ScriptRegistry, install_builtin_scripts
    script_base = install_builtin_scripts()
    registry = ScriptRegistry([script_base])
    matching_scripts = registry.search(query)
    
    SEV_COLORS = {
        "CRITICAL": "\033[38;5;196;1m",
        "HIGH": "\033[38;5;202;1m",
        "MEDIUM": "\033[38;5;220;1m",
        "LOW": "\033[38;5;82;1m",
        "INFO": "\033[38;5;39;1m"
    }
    
    if matching_templates:
        title = f"VULNERABILITY TEMPLATES ({len(matching_templates)} matches)"
        rem = max(2, 76 - 5 - len(title))
        print(f"\033[38;5;196m┌───\033[0m \033[1m{title}\033[0m \033[38;5;196m" + "─" * rem + "\033[0m")
        print(f"  \033[38;5;244m%-10s %-32s %-20s %-10s %s\033[0m" % ("SEVERITY", "ID", "CVE", "PORT", "TAGS"))
        print(f"  " + "\033[38;5;238m─\033[0m" * 74)
        for tmpl in sorted(matching_templates, key=lambda x: (x.severity.value, x.id)):
            cve = tmpl.cve if tmpl.cve else "-"
            tags = ",".join(tmpl.tags[:3])
            col = SEV_COLORS.get(tmpl.severity.value.upper(), "\033[0m")
            print(f"  {col}%-10s\033[0m %-32s %-20s %-10s \033[38;5;242m[%s]\033[0m" % (
                tmpl.severity.value, tmpl.id[:32], cve[:20], str(tmpl.port), tags
            ))
        print(f"\033[38;5;196m└" + "─" * 76 + "\033[0m\n")
        
    if matching_scripts:
        title = f"RECON & DETECTION SCRIPTS ({len(matching_scripts)} matches)"
        rem = max(2, 76 - 5 - len(title))
        print(f"\033[38;5;39m┌───\033[0m \033[1m{title}\033[0m \033[38;5;39m" + "─" * rem + "\033[0m")
        print(f"  \033[38;5;244m%-30s %-18s %s\033[0m" % ("SCRIPT NAME", "PORTS", "TAGS"))
        print(f"  " + "\033[38;5;238m─\033[0m" * 74)
        for s in matching_scripts:
            tags = ",".join(s['tags'][:3])
            ports = ",".join(map(str, s['ports'][:4])) if s['ports'] else "all"
            print(f"  \033[38;5;111m%-30s\033[0m %-18s \033[38;5;242m[%s]\033[0m" % (
                s['name'][:30], ports[:18], tags
            ))
            if s['desc']:
                desc = s['desc'].strip().replace("\n", " ")
                desc_lines = [desc[i:i+70] for i in range(0, len(desc), 70)]
                for line in desc_lines[:2]:
                    print(f"    \033[38;5;240m\u21aa {line.strip()}\033[0m")
        print(f"\033[38;5;39m└" + "─" * 76 + "\033[0m\n")
        
    if not matching_templates and not matching_scripts:
        print(f"\033[38;5;240m[-] No matching templates or scripts found for {query!r}\033[0m\n")

def run_update_templates(repo_spec: str):
    import urllib.request
    import zipfile
    import shutil
    import tempfile
    from pathlib import Path
    
    if "/" not in repo_spec:
        print(f"\033[38;5;208m[!] Invalid repo format. Must be owner/repo (e.g., ne0k1r4/LightScan)\033[0m")
        return
        
    owner, repo = repo_spec.split("/", 1)
    url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
    
    print(f"\033[38;5;196m[UPDATE]\033[0m Downloading templates from: {url}")
    
    local_template_dir = Path(__file__).parent / "templates"
    
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        
        with urllib.request.urlopen(req, timeout=15) as response:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_file:
                shutil.copyfileobj(response, tmp_file)
                tmp_zip_path = Path(tmp_file.name)
                
        print(f"\033[38;5;196m[UPDATE]\033[0m Extracting templates...")
        
        with zipfile.ZipFile(tmp_zip_path, 'r') as zip_ref:
            extracted_count = 0
            for file_info in zip_ref.infolist():
                parts = Path(file_info.filename).parts
                if len(parts) >= 3 and "templates" in parts:
                    tpl_idx = parts.index("templates")
                    if tpl_idx > 0 and parts[tpl_idx - 1] == "lightscan":
                        rel_path = Path(*parts[tpl_idx + 1:])
                        target_path = local_template_dir / rel_path
                        
                        if file_info.is_dir():
                            target_path.mkdir(parents=True, exist_ok=True)
                        else:
                            target_path.parent.mkdir(parents=True, exist_ok=True)
                            with zip_ref.open(file_info) as source, open(target_path, "wb") as target:
                                shutil.copyfileobj(source, target)
                            extracted_count += 1
                            
        try:
            tmp_zip_path.unlink()
        except Exception:
            pass
            
        if extracted_count > 0:
            print(f"\033[38;5;82m[+] Successfully updated {extracted_count} templates from {repo_spec}!\033[0m\n")
        else:
            print(f"\033[38;5;208m[!] No templates found in the repository archive.\033[0m\n")
            
    except Exception as e:
        print(f"\033[38;5;196m[!] Error updating templates: {e}\033[0m")

async def _run_main_body(args, cp, t_start, all_results, open_ports, meta):
    if getattr(args, "import_nmap_xml", None):
        from lightscan.core.nmap_xml import NmapXMLImportError, import_nmap_xml

        try:
            imported, import_summary = import_nmap_xml(args.import_nmap_xml)
        except NmapXMLImportError as exc:
            print(f"\033[38;5;208m[!] Unable to import Nmap XML: {exc}\033[0m", file=sys.stderr)
            return all_results
        all_results.extend(imported)
        os_evidence_count = 0
        if getattr(args, "os_evidence", False):
            from lightscan.scan.os_evidence import infer_os_from_results

            os_evidence = infer_os_from_results(all_results)
            os_evidence_count = len(os_evidence)
            all_results.extend(os_evidence)
        meta["nmap_import"] = import_summary
        print(
            f"\033[38;5;82m[+] Imported Nmap XML: {import_summary['hosts_imported']} host(s), "
            f"{import_summary['os_observations']} OS observation(s), "
            f"{import_summary['service_observations']} open-service observation(s), "
            f"{os_evidence_count} passive OS-evidence observation(s)\033[0m"
        )
        if not args.no_report and all_results:
            Reporter(args.output).save(all_results, meta, args.basename, fmt=args.format)
        return all_results

    if getattr(args, "compare_metrics", None):
        from lightscan.core.metrics import compare_snapshots

        baseline, candidate = args.compare_metrics
        try:
            comparison = compare_snapshots(baseline, candidate)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"\033[38;5;208m[!] Unable to compare metrics: {exc}\033[0m", file=sys.stderr)
            return all_results
        print(json.dumps(comparison, indent=2, sort_keys=True))
        return all_results

    if getattr(args, 'search', None):
        await run_search(args.search)
        return all_results

    if getattr(args, 'update_templates', None):
        run_update_templates(args.update_templates)
        return all_results

    if getattr(args, 'auto', None):
        from lightscan.scan.orchestrator import run_auto
        scope     = getattr(args, 'scope', None) or []
        stealth   = getattr(args, 'stealth', False)
        intensity = getattr(args, 'intensity', 3)
        ports     = parse_ports(args.ports) if args.ports != "top100" else None
        users     = parse_userlist(args.users)  if args.users    else None
        passwords = parse_passwdlist(args.wordlist, mutate=args.mutate) if args.wordlist else None
        results, comp_map = await run_auto(
            domain     = args.auto,
            scope      = scope,
            timeout    = args.timeout,
            intensity  = intensity,
            stealth    = stealth,
            ports      = ports,
            userlist   = users,
            passlist   = passwords,
            skip_web   = getattr(args, 'skip_web', False),
            skip_brute = getattr(args, 'skip_brute', False),
            output_dir = args.output,
            mode       = getattr(args, 'mode', 'deep'),
            allow_intrusive = getattr(args, 'allow_exploit', False),
        )
        all_results.extend(results)
        if not args.no_report and all_results:
            Reporter(args.output).save(all_results, meta, args.basename, fmt=args.format)
        return all_results

    if getattr(args, 'active', False) and args.target:
        from lightscan.scan.active import active_scan
        hosts     = _targets(args)
        intensity = getattr(args, 'intensity', 3)
        scope     = getattr(args, 'scope', None) or []
        if scope:
            import ipaddress as _ip
            def _in_scope(h):
                for s in scope:
                    try:
                        if _ip.ip_address(h) in _ip.ip_network(s, strict=False): return True
                    except ValueError:
                        if h == s or h.endswith("." + s): return True
                return False
            filtered = [h for h in hosts if _in_scope(h)]
            dropped  = len(hosts) - len(filtered)
            if dropped:
                print(f"\033[38;5;240m[SCOPE] Dropped {dropped} out-of-scope host(s)\033[0m")
            hosts = filtered
        if not hosts:
            print("\033[38;5;208m[!] No in-scope targets to scan.\033[0m")
            return all_results
        cdn_hosts = []
        if getattr(args, 'exclude_cdn', False):
            hosts, cdn_hosts = _split_cdn_hosts(hosts)
            if not hosts and not cdn_hosts:
                print("\033[38;5;208m[!] No targets left after CDN split.\033[0m")
                return all_results
        ports = parse_ports(args.ports) if args.ports != "top100" else None
        results = []
        if hosts:
            results += await active_scan(
                targets     = hosts,
                ports       = ports,
                timeout     = args.timeout,
                concurrency = args.concurrency,
                intensity   = intensity,
                verbose     = args.verbose,
                mode        = getattr(args, 'mode', 'deep'),
            )
        if cdn_hosts:
            results += await active_scan(
                targets     = cdn_hosts,
                ports       = [80, 443],
                timeout     = args.timeout,
                concurrency = args.concurrency,
                intensity   = intensity,
                verbose     = args.verbose,
                mode        = getattr(args, 'mode', 'deep'),
            )
        all_results.extend(results)
        if not args.no_report and all_results:
            Reporter(args.output).save(all_results, meta, args.basename, fmt=args.format)
        return all_results

    if args.diff:
        from lightscan.scan.diff import diff_scans
        old_f,new_f=args.diff
        results,summary=diff_scans(old_f,new_f)
        print(f"\033[38;5;196m[DIFF]\033[0m {summary}")
        all_results.extend(results)

    if args.dns:
        from lightscan.scan.dns import full_dns_enum
        r=await full_dns_enum(args.dns,axfr=not args.no_axfr,
            brute=not args.no_brute_dns,use_crtsh=not args.no_crtsh)
        all_results.extend(r)

    if getattr(args, 'os_probe', False) and args.target:
        from lightscan.scan.os_detect import os_probe_async
        hosts = _targets(args)
        print(f"\033[38;5;196m[OS-PROBE]\033[0m Active fingerprinting {len(hosts)} host(s)")
        for host in hosts:
            probe_port = getattr(args, 'os_port', None)
            if not probe_port:
                probe_port = open_ports.get(host, [80])[0] if open_ports.get(host) else 80
            os_results = await os_probe_async(host, probe_port)
            for r in os_results:
                print(f"  \033[38;5;196m[OS]\033[0m {r.target} → {r.detail}")
            all_results.extend(os_results)

    if getattr(args, 'os_passive', False) and not (args.syn or getattr(args,'syn_c',False)) and args.target:
        print(f"\033[38;5;240m[!] --os-passive works best with --syn (reads SYN-ACK packets)\033[0m")
        print(f"\033[38;5;240m    Without --syn, TTL-only estimation will be LOW confidence\033[0m")

    if getattr(args, 'web_scan', None):
        from lightscan.web.scanner import web_scan_async
        print(f"\033[38;5;196m[WEB-SCAN]\033[0m {args.web_scan}")
        web_results = await web_scan_async(
            args.web_scan,
            wordlist_file = getattr(args, 'web_wordlist', None),
            timeout  = args.timeout,
            threads  = getattr(args, 'web_threads', 10),
            checks   = getattr(args, 'web_checks', None),
        )
        all_results.extend(web_results)
        counts = {}
        for r in web_results:
            counts[r.severity.value] = counts.get(r.severity.value, 0) + 1
        SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        summary = " | ".join(
            f"{counts[s]} {s}" for s in SEV_ORDER if s in counts
        )
        print(f"  \033[38;5;196m[WEB-SCAN DONE]\033[0m {len(web_results)} findings — {summary}")

        SEV_COLOR = {"CRITICAL":"\033[38;5;196m","HIGH":"\033[38;5;208m",
                     "MEDIUM":"\033[38;5;226m","LOW":"\033[38;5;40m","INFO":"\033[38;5;240m"}
        for result in web_results:
            sev = result.severity.value
            if sev not in ("CRITICAL","HIGH","MEDIUM"): continue
            col  = SEV_COLOR.get(sev,"\033[0m")
            print(f"    {col}[{sev}]\033[0m {result.module} — {result.detail}")
            location = result.data.get("url") or result.data.get("path")
            if location:
                print(f"      \033[38;5;240m↳ {location}\033[0m")

    if getattr(args, 'rdp_probe', None):
        from lightscan.brute.handlers.rdp_raw import make_rdp_probe, RawRDPHandler
        print(f"\033[38;5;196m[RDP-PROBE]\033[0m {args.rdp_probe}")
        info = make_rdp_probe(args.rdp_probe, timeout=args.timeout)
        for k, v in info.items():
            print(f"  {k:<18}: {v}")
        sev = Severity.HIGH if info.get("nla_required") else Severity.CRITICAL
        all_results.append(ScanResult("rdp-probe", args.rdp_probe, 3389,
            info.get("status","?"), sev,
            f"RDP proto={info.get('protocol','?')} NLA={info.get('nla_required','?')}",
            info))

    if args.traceroute:
        from lightscan.scan.traceroute import tcp_traceroute
        tr=await tcp_traceroute(args.traceroute,timeout=args.timeout)
        for hop in tr: print(f"  {hop.detail}")
        all_results.extend(tr)

    if (args.syn or getattr(args, 'syn_c', False)) and args.target:
        from lightscan.scan.syn import syn_scan_auto
        hosts = _targets(args); ports = parse_ports(args.ports)
        syn_results = []
        for host in hosts:
            r = syn_scan_auto(host, ports, args.timeout,
                              getattr(args,'threads',100), args.verbose,
                              prefer_c=getattr(args,'syn_c',False))
            syn_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")
        all_results.extend(syn_results)

    if args.udp and args.target:
        from lightscan.scan.udp import udp_scan
        udp_ports_default = [53, 67, 68, 69, 111, 123, 137, 161, 162,
                             389, 500, 514, 520, 1900, 4500, 5353, 5060]
        ports = parse_ports(args.ports) if args.ports else udp_ports_default
        hosts = _targets(args)
        udp_results = []
        for host in hosts:
            r = udp_scan(host, ports, args.timeout,
                         getattr(args, 'threads', 50), args.verbose)
            udp_results.extend(r)
        for res in udp_results:
            colour = "\033[38;5;196m" if res.status == "open" else "\033[38;5;240m"
            print(f"  {colour}{res.status.upper():<13}\033[0m  "
                  f"{res.target}:{res.port:<6} {res.detail}")
        all_results.extend(udp_results)

    if getattr(args, 'raw', False) and args.target:
        from lightscan.scan.rawscan import async_raw_scan
        hosts  = _targets(args)
        ports  = parse_ports(args.ports)
        timing = parse_timing(getattr(args, 'timing', 'T4'))
        ttl    = getattr(args, 'ttl', 64)
        decoys = getattr(args, 'decoy', 0)
        frag   = getattr(args, 'fragment', False)
        rand   = not getattr(args, 'no_randomize', False)
        ipv6   = getattr(args, 'ipv6', False)
        print(f"\033[38;5;196m[RAW-SCAN]\033[0m {len(hosts)} host(s) × {len(ports)} ports | "
              f"T{timing} | ttl={ttl} | decoys={decoys} | frag={frag}")
        for host in hosts:
            r = await async_raw_scan(host, ports, timing=timing, ttl=ttl,
                                     decoys=decoys, fragment=frag, randomize=rand,
                                     grab_banner=True, verbose=args.verbose, ipv6=ipv6)
            all_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")

    if getattr(args, 'ipv6', False) and args.target and not getattr(args, 'raw', False):
        from lightscan.scan.ipv6scan import scan_ipv6, dual_stack_scan
        hosts = _targets(args)
        ports = parse_ports(args.ports)
        for host in hosts:
            if getattr(args, 'dual_stack', False):
                r = await dual_stack_scan(host, ports, args.timeout,
                                          args.concurrency, verbose=args.verbose)
            else:
                r = await scan_ipv6(host, ports, args.timeout,
                                    args.concurrency, verbose=args.verbose)
            all_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")

    if getattr(args, 'os_v2', False) and args.target:
        from lightscan.scan.osdb import probe_os
        hosts = _targets(args)
        print(f"\033[38;5;196m[OS-V2]\033[0m Fingerprinting {len(hosts)} host(s)")
        for host in hosts:
            port = list(open_ports.get(host, [0]))[0] if open_ports.get(host) else 0
            r = await probe_os(host, port, args.timeout)
            all_results.extend(r)
            for res in r:
                print(f"  \033[38;5;196m[OS]\033[0m {res.target} → {res.detail}")

    _do_packet = getattr(args, 'packet_scan', False) or getattr(args, 'stealth_scan', False)
    if _do_packet and args.target:
        from lightscan.scan.packetscan import async_packet_scan
        hosts       = _targets(args)
        ports       = parse_ports(args.ports)
        timing      = parse_timing(getattr(args, 'timing', 'T4'))
        stealth     = getattr(args, 'stealth_scan', False)
        spoof_sport = getattr(args, 'spoof_sport', 0)
        for host in hosts:
            r = await async_packet_scan(
                host, ports, timing=timing,
                ttl=getattr(args, 'ttl', 64),
                grab_banner=True, verbose=args.verbose,
                stealth=stealth, spoof_sport=spoof_sport)
            all_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m     {res.target}:{res.port:<6} {res.detail}")
                elif res.status == "firewall":
                    print(f"  \033[38;5;208mFIREWALL\033[0m {res.target}:{res.port:<6} {res.detail}")

    if getattr(args, 'list_scripts', False):
        from lightscan.scan.scripts import ScriptRegistry, install_builtin_scripts
        script_base = install_builtin_scripts()
        registry    = ScriptRegistry([script_base])
        
        s_tags = getattr(args, 'script_tags', None)
        s_ports = parse_ports(args.ports) if args.ports != "top100" else None
        
        scripts = registry.list_all()
        if s_tags:
            scripts = [s for s in scripts if any(t in s['tags'] for t in s_tags)]
        if s_ports:
            scripts = [s for s in scripts if not s['ports'] or any(p in s['ports'] for p in s_ports)]
            
        if s_tags or s_ports:
            print(f"\033[38;5;196m[SCRIPTS]\033[0m Found {len(scripts)} matching script(s)\n")
        else:
            print(f"\033[38;5;196m[SCRIPTS]\033[0m {len(registry)} scripts available\n")
            
        for s in scripts:
            print(f"  {s['name']:<30} [{', '.join(s['tags'][:3])}]  ports={s['ports'][:4]}")
            if s['desc']: print(f"    {s['desc']}")
        return all_results

    if (getattr(args, 'script', None) or getattr(args, 'script_tags', None)) and args.target:
        from lightscan.scan.scripts import run_scripts, install_builtin_scripts
        hosts       = _targets(args)
        script_base = install_builtin_scripts()
        for host in hosts:
            ports = open_ports.get(host, parse_ports(args.ports))
            r = await run_scripts(
                host, ports,
                script_dirs=[script_base],
                names=getattr(args, 'script', None),
                tags=getattr(args, 'script_tags', None),
                timeout=args.timeout, verbose=args.verbose)
            all_results.extend(r)

    if getattr(args, 'sv', False) and args.target and not getattr(args, 'scan', False):
        from lightscan.scan.sversion import detect_services
        hosts = _targets(args)
        print(f"\033[38;5;196m[sV]\033[0m Service version detection | {len(hosts)} host(s)")
        for host in hosts:
            ports = open_ports.get(host, parse_ports(args.ports))
            if not ports:
                continue
            r = await detect_services(
                host,
                ports,
                args.timeout,
                concurrency=args.version_concurrency,
                verbose=args.verbose,
            )
            all_results.extend(r)
            for res in r:
                print(f"  \033[38;5;196m[{res.port}]\033[0m {res.detail}")

    if getattr(args, 'passive', False) and args.target:
        from lightscan.scan.passive import passive_fingerprint
        hosts = _targets(args)
        print(f"\033[38;5;196m[PASSIVE]\033[0m Passive fingerprinting | {len(hosts)} host(s)")
        for host in hosts:
            ports = open_ports.get(host, parse_ports(args.ports))
            if not ports: continue
            r = await passive_fingerprint(host, ports, args.timeout)
            all_results.extend(r)
            for res in r:
                print(f"  \033[38;5;196m[{res.module}]\033[0m {res.detail}")

    if args.scan and args.target:
        from lightscan.scan.streaming import ScanControls, StreamingTCPScanner

        hosts = _targets(args)
        ports = parse_ports(args.ports)
        cdn_hosts = []
        if getattr(args, 'exclude_cdn', False):
            hosts, cdn_hosts = _split_cdn_hosts(hosts)
        cdn_note = f" ({len(cdn_hosts)} CDN host(s) restricted to 80,443)" if cdn_hosts else ""
        controls = ScanControls(
            concurrency=args.concurrency,
            per_host_concurrency=args.per_host_concurrency,
            max_rate=args.max_rate,
            retries=args.retries,
            retry_jitter=args.retry_jitter,
            host_timeout=args.host_timeout,
            host_group_size=args.host_group_size,
            adaptive=getattr(args, "adaptive", False),
            timing=parse_timing(getattr(args, "timing", "T4")),
        )
        engine_name = "go" if args.go_engine else "streaming-python"
        print(
            f"\033[38;5;196m[SCAN]\033[0m {engine_name} engine | "
            f"{len(hosts)+len(cdn_hosts)} host(s) × {len(ports)} port(s){cdn_note} | "
            f"concurrency={controls.concurrency} per-host={controls.per_host_concurrency} "
            f"rate={controls.max_rate or 'unlimited'} retry-jitter={controls.retry_jitter}"
        )

        scan_r = []
        performance = {"engine": engine_name, "controls": controls.__dict__.copy()}
        stream_writer = None
        retain_results = not bool(args.stream_open)
        if args.stream_open:
            from lightscan.core.ndjson import NDJSONResultWriter

            stream_writer = NDJSONResultWriter(args.stream_open, meta)
        if args.go_engine:
            from lightscan.scan.go_runner import GoScannerError, scan_with_go
            try:
                scan_r, go_metadata = await scan_with_go(
                    hosts,
                    ports,
                    timeout=args.timeout,
                    controls=controls,
                    banners=not args.no_banner_grab,
                    binary_path=args.go_binary,
                    result_sink=stream_writer.emit if stream_writer else None,
                    retain_results=retain_results,
                )
                if cdn_hosts:
                    cdn_results, cdn_metadata = await scan_with_go(
                        cdn_hosts,
                        [80, 443],
                        timeout=args.timeout,
                        controls=controls,
                        banners=not args.no_banner_grab,
                        binary_path=args.go_binary,
                        result_sink=stream_writer.emit if stream_writer else None,
                        retain_results=retain_results,
                    )
                    scan_r.extend(cdn_results)
                    go_metadata["cdn"] = cdn_metadata
                performance.update(go_metadata)
            except GoScannerError as exc:
                print(f"\033[38;5;208m[!] Go scan engine unavailable: {exc}\033[0m")
                return all_results
        else:
            scanner = StreamingTCPScanner(
                controls,
                timeout=args.timeout,
                banners=not args.no_banner_grab,
                result_sink=stream_writer.emit if stream_writer else None,
            )
            scan_r = await scanner.scan(hosts, ports, retain_results=retain_results)
            if cdn_hosts:
                scan_r.extend(
                    await scanner.scan(cdn_hosts, [80, 443], retain_results=retain_results)
                )
            performance["metrics"] = scanner.metrics.to_dict()
            performance["adaptive"] = scanner.adaptive_summary
            if args.verbose:
                metrics = performance["metrics"]
                print(
                    f"\033[38;5;240m[~] streaming: {metrics['attempts']} attempts | "
                    f"{metrics['open']} open | {metrics['filtered']} filtered | "
                    f"{metrics['elapsed']:.2f}s\033[0m"
                )

        if stream_writer is not None:
            stream_writer.close(performance)
            print(f"\033[38;5;82m[+] Open-port stream: {stream_writer.path}\033[0m")
        if args.metrics_out:
            from lightscan.core.metrics import write_snapshot

            metrics_path = write_snapshot(args.metrics_out, performance, meta)
            print(f"\033[38;5;82m[+] Performance metrics: {metrics_path}\033[0m")
        meta["performance"] = performance
        all_results.extend(scan_r)
        for r in scan_r:
            if r.status == "open":
                open_ports.setdefault(r.target, []).append(r.port)
                print(f"  \033[38;5;196mOPEN  {r.target}:{r.port:<6} {r.detail}\033[0m")

        if getattr(args, "sv", False) and open_ports:
            from lightscan.scan.sversion import detect_services

            print(f"\033[38;5;196m[sV]\033[0m Service version detection on confirmed open ports")
            for host, confirmed_ports in sorted(open_ports.items()):
                version_results = await detect_services(
                    host,
                    confirmed_ports,
                    args.timeout,
                    concurrency=args.version_concurrency,
                    verbose=args.verbose,
                )
                all_results.extend(version_results)
                for result in version_results:
                    print(f"  \033[38;5;196m[{result.port}]\033[0m {result.detail}")

    if getattr(args, "list_lua_scripts", False) or (
        (getattr(args, "lua_script", None) or getattr(args, "lua_script_tags", None))
        and args.target
    ):
        from pathlib import Path
        from lightscan.scan.lua_checks import LuaCheckError, LuaCheckRegistry, run_lua_checks

        lua_roots = [str(Path(__file__).parent / "lua_scripts")]
        lua_roots.extend(getattr(args, "lua_script_dir", None) or [])
        registry = LuaCheckRegistry(lua_roots)
        try:
            registry.discover()
            if getattr(args, "list_lua_scripts", False):
                checks = registry.list_all()
                print(f"\033[38;5;196m[LUA CHECKS]\033[0m {len(checks)} safe check(s) available\n")
                for check in checks:
                    print(
                        f"  {check['name']:<30} "
                        f"[{', '.join(check['categories'])}] ports={check['ports'] or 'any'}"
                    )
                    print(f"    {check['description']}")
                if not (getattr(args, "lua_script", None) or getattr(args, "lua_script_tags", None)):
                    return all_results

            if getattr(args, "lua_script", None) or getattr(args, "lua_script_tags", None):
                if not open_ports:
                    print("\033[38;5;208m[!] Lua checks require confirmed open ports. "
                          "Run them with --scan against authorized assets.\033[0m")
                else:
                    print("\033[38;5;196m[LUA CHECKS]\033[0m "
                          "Executing constrained, non-destructive checks on confirmed open ports")
                    for host, confirmed_ports in sorted(open_ports.items()):
                        findings = await run_lua_checks(
                            host,
                            confirmed_ports,
                            registry,
                            names=getattr(args, "lua_script", None),
                            categories=getattr(args, "lua_script_tags", None),
                            timeout=args.timeout,
                            concurrency=args.lua_concurrency,
                        )
                        all_results.extend(findings)
                        for finding in findings:
                            print(
                                f"  \033[38;5;196m[{finding.severity.value}]\033[0m "
                                f"{finding.module} @ {finding.target}:{finding.port} — {finding.detail}"
                            )
        except LuaCheckError as exc:
            print(f"\033[38;5;208m[!] Lua check error: {exc}\033[0m")
            if getattr(args, "list_lua_scripts", False):
                return all_results

    if getattr(args, 'list_templates', False):
        from lightscan.cve.template_engine import TemplateLibrary
        from pathlib import Path
        dirs = [str(Path(__file__).parent / "templates")]
        if getattr(args, 'template_dir', None): dirs.append(args.template_dir)
        lib = TemplateLibrary(dirs)
        
        t_tags = getattr(args, 'template_tags', None)
        t_ids = getattr(args, 'template_ids', None)
        templates = lib.filter(tags=t_tags, ids=t_ids) if (t_tags or t_ids) else list(lib)
        
        if t_tags or t_ids:
            print(f"\033[38;5;196m[TEMPLATES]\033[0m Found {len(templates)} matching template(s)")
        else:
            print(f"\033[38;5;196m[TEMPLATES]\033[0m {lib.summary()}")
            
        for tmpl in sorted(templates, key=lambda x: (x.severity.value, x.id)):
            cve = f" {tmpl.cve}" if tmpl.cve else ""
            tags = ",".join(tmpl.tags[:4])
            print(f"  {tmpl.severity.value:<8} {tmpl.id:<35}{cve:<22} [{tags}]  port={tmpl.port}")
        return all_results

    run_cve       = args.cve
    run_templates = getattr(args, 'templates', False)
    if (run_cve or run_templates) and args.target:
        from lightscan.cve.bridge import run_all_checks, versions_from_results
        from lightscan.cve.template_engine import TemplateLibrary
        hosts = _targets(args) if not open_ports else list(open_ports.keys())
        extra_dirs = [args.template_dir] if getattr(args, 'template_dir', None) else None
        t_tags     = getattr(args, 'template_tags', None)
        t_ids      = getattr(args, 'template_ids', None)
        cb         = args.log4shell_callback or ""
        use_legacy = run_cve
        versions   = versions_from_results(all_results)
        allow_exploit = getattr(args, 'allow_exploit', False)

        if allow_exploit:
            from pathlib import Path as _Path
            lib = TemplateLibrary([str(_Path(__file__).parent / "templates")] + (extra_dirs or []))
            intrusive_ids = [t.id for t in lib.filter(tags=t_tags, ids=t_ids) if t.intrusive]
            if intrusive_ids:
                print(f"\033[38;5;208m[!] --allow-exploit is set — these templates will actually run a "
                      f"command / read a file / inject sql on a hit, not just detect:\033[0m")
                for tid in intrusive_ids:
                    print(f"      {tid}")

        print(f"\033[38;5;196m[{'CVE+TPL' if run_cve else 'TEMPLATES'}]\033[0m {len(hosts)} host(s)")
        for host in hosts:
            r = await run_all_checks(
                host, open_ports.get(host, []),
                template_dirs=extra_dirs,
                template_tags=t_tags,
                template_ids=t_ids,
                use_legacy=use_legacy,
                log4shell_callback=cb,
                versions=versions,
                allow_intrusive=allow_exploit,
                timeout=args.timeout,
            )
            all_results.extend(r)
            for res in r:
                if res.status not in ("not_vuln","not_detected","error","no_response",
                                      "timeout","not_tls","not_enabled"):
                    print(f"  \033[38;5;196m[{res.severity.value}]\033[0m "
                          f"{res.module} @ {res.target}:{res.port} — {res.detail[:80]}")

    if args.oauth:
        cid=args.oauth_client or "00000000-0000-0000-0000-000000000000"
        red=args.oauth_redirect or "https://localhost/callback"
        scanner=OAuthScanner(args.oauth,cid,red,args.timeout)
        all_results.extend(await scanner.scan_all())

    if args.brute and args.target:
        from lightscan.brute.engine import BruteEngine, CredentialSpray
        from lightscan.brute.handlers import get_handler, PROTOCOLS
        proto=args.brute.lower(); hosts=_targets(args)
        users=parse_userlist(args.users)
        target_info={"domain":args.target if "." in args.target else ""}
        passwords=parse_passwdlist(args.wordlist,users,target_info,args.mutate)
        jitter=tuple(args.jitter) if args.jitter else (0.0,0.0)
        brute=BruteEngine(concurrency=args.brute_conc,timeout=args.timeout,
                          jitter=jitter,checkpoint=cp if args.resume else None,verbose=args.verbose)
        print(f"\033[38;5;196m[BRUTE]\033[0m {proto.upper()} | {len(hosts)} host(s) | {len(users)} users | {len(passwords)} passwords")

        for host in hosts:
            port=args.brute_port
            if proto=="http":
                if not args.http_url: print("  [!] --http-url required for --brute http"); continue
                handler=get_handler(proto,host,port,url=args.http_url,
                    user_field=args.http_user_field,pass_field=args.http_pass_field,
                    success_text=args.http_success,failure_text=args.http_failure,
                    basic_auth=args.http_basic)
            else:
                handler=get_handler(proto,host,port)

            from lightscan.brute.handlers import PROTOCOLS as PH
            _,dport=PH[proto]; actual_port=port or dport

            if args.spray:
                spray=CredentialSpray(args.spray_window)
                pairs=[(u,p) async for u,p in spray.pairs(users,passwords)]
                u_s=list(dict.fromkeys(u for u,_ in pairs))
                p_s=list(dict.fromkeys(p for _,p in pairs))
                r=await brute.run(handler,u_s,p_s,host,actual_port,proto,args.stop_first)
            else:
                r=await brute.run(handler,users,passwords,host,actual_port,proto,args.stop_first)
            all_results.extend(r)

    if getattr(args, "os_evidence", False):
        from lightscan.scan.os_evidence import infer_os_from_results

        os_evidence = infer_os_from_results(all_results)
        all_results.extend(os_evidence)
        if os_evidence and not getattr(args, "quiet", False):
            print(f"\033[38;5;240m[i] Added {len(os_evidence)} OS-evidence observation(s) without extra probes\033[0m")

    SEV_MAP = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    min_rank = SEV_MAP.get(getattr(args, "min_severity", "info").lower(), 1)
    if min_rank > 1:
        all_results = [r for r in all_results if hasattr(r, "severity") and SEV_MAP.get(r.severity.value.lower(), 1) >= min_rank]

    elapsed=time.time()-t_start; meta["duration"]=elapsed
    crit=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="CRITICAL")
    high=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="HIGH")
    med=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="MEDIUM")
    low=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="LOW")
    info=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="INFO")
    
    high_critical_findings = [r for r in all_results if hasattr(r,"severity") and r.severity.value in ("CRITICAL", "HIGH")]
    
    if not getattr(args, "quiet", False):
        print()
        if high_critical_findings:
            print(f"\033[38;5;196m┌───\033[0m \033[1mCRITICAL & HIGH FINDINGS SUMMARY\033[0m \033[38;5;196m" + "─" * 40 + "\033[0m")
            print(f"  \033[38;5;244m%-10s %-20s %-8s %-38s\033[0m" % ("SEVERITY", "TARGET", "PORT", "DETAILS"))
            print(f"  " + "\033[38;5;238m─\033[0m" * 74)
            for r in high_critical_findings:
                col = "\033[38;5;196;1m" if r.severity.value == "CRITICAL" else "\033[38;5;202;1m"
                print(f"  {col}%-10s\033[0m %-20s %-8s %-38s" % (
                    r.severity.value, r.target[:20], str(r.port) if r.port else "-", r.detail[:38]
                ))
            print(f"\033[38;5;196m└" + "─" * 76 + "\033[0m\n")

        C = "\033[38;5;196m"; YEL = "\033[38;5;208m"; GRN = "\033[38;5;82m"; R = "\033[0m"
        print(f"{C}┌───────────────────────────────────────────────────────────────┐{R}")
        print(f"{C}│                      SCAN EXECUTION COMPLETE                  │{R}")
        print(f"{C}├───────────────────────────────────────────────────────────────┤{R}")
        print(f"{C}│{R}  Total Duration : {f'{elapsed:.1f}s':<44} {C}│{R}")
        print(f"{C}│{R}  Total Findings : {len(all_results):<44} {C}│{R}")
        print(f"{C}│{R}  {C}CRITICAL{R}       : {C}{crit:<44}{R} {C}│{R}")
        print(f"{C}│{R}  {YEL}HIGH{R}           : {YEL}{high:<44}{R} {C}│{R}")
        print(f"{C}│{R}  MEDIUM         : {med:<44} {C}│{R}")
        print(f"{C}│{R}  LOW / INFO     : {f'{low} / {info}':<44} {C}│{R}")
        if not args.no_report and all_results:
            base = args.basename or f"lightscan_report_{int(t_start)}"
            saved_part = f"{base}.html / .json"
            print(f"{C}│{R}  Saved Report   : {GRN}{saved_part:<44}{R} {C}│{R}")
        print(f"{C}└───────────────────────────────────────────────────────────────┘{R}\n")

    if not args.no_report and all_results:
        Reporter(args.output).save(all_results, meta, args.basename, fmt=args.format)
    return all_results


_DEFAULT_CONCURRENCY = 256
_FD_SAFETY_MARGIN    = 100

def _tune_concurrency(requested: int | None) -> int:
    """
    rustscan does this by checking ulimit and sizing its batch to fit under
    it instead of handing out a fixed number and hoping. same idea here -
    the ulimit raise above is a best-effort attempt, this checks what we
    actually ended up with and reacts to it either way.
    """
    if sys.platform == "win32":
        return requested if requested is not None else _DEFAULT_CONCURRENCY
    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:
        return requested if requested is not None else _DEFAULT_CONCURRENCY

    if requested is not None:
        if requested + _FD_SAFETY_MARGIN > soft:
            print(f"\033[38;5;208m[!] --concurrency {requested} is close to or above your open-file "
                  f"limit ({soft}) - expect connection errors mid-scan. raise it first with "
                  f"'ulimit -n {requested + _FD_SAFETY_MARGIN}', or lower --concurrency.\033[0m", file=sys.stderr)
        return requested

    if soft - _FD_SAFETY_MARGIN < _DEFAULT_CONCURRENCY:
        tuned = max((soft // 2) if soft < _DEFAULT_CONCURRENCY else soft - _FD_SAFETY_MARGIN, 8)
        print(f"\033[38;5;208m[!] open-file limit is {soft}, too low for the usual default (256) - "
              f"scaling concurrency down to {tuned} to avoid mid-scan socket errors. "
              f"'ulimit -n {_DEFAULT_CONCURRENCY + _FD_SAFETY_MARGIN}' gets full speed back.\033[0m", file=sys.stderr)
        return tuned

    if soft > (_DEFAULT_CONCURRENCY + _FD_SAFETY_MARGIN) * 4:
        print(f"\033[38;5;240m[i] open-file limit is {soft} - plenty of headroom, "
              f"try --concurrency {min(soft - _FD_SAFETY_MARGIN, 4096)} for a faster scan.\033[0m", file=sys.stderr)

    return _DEFAULT_CONCURRENCY

def _split_cdn_hosts(hosts: list[str]) -> tuple[list[str], list[str]]:
    """
    naabu does this before deciding on a full port sweep - resolve each
    host, check it against known cloudflare/fastly ranges, and split into
    (normal, cdn) so the caller can scan cdn ones with a restricted port
    list instead of hammering someone else's edge network for no reason.
    only called when --exclude-cdn is actually set, so this resolve step
    doesn't add overhead to the common case.
    """
    from lightscan.scan.cdn import is_cdn_ip
    normal, cdn = [], []
    for h in hosts:
        ip = resolve(h) or h
        matched, provider = is_cdn_ip(ip)
        if matched:
            cdn.append(h)
            print(f"\033[38;5;240m[i] {h} ({ip}) is behind {provider} - "
                  f"restricting to 80,443 instead of the full port list\033[0m")
        else:
            normal.append(h)
    return normal, cdn

def main():
    argv = normalize_command_argv(sys.argv[1:])
    if argv and argv[0] == "report":
        from lightscan.commands.report import main as report_main

        raise SystemExit(report_main(argv[1:]))

    if sys.platform != "win32":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            if soft < hard:
                resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        except Exception:
            pass

    if not argv:
        print_banner()
        print("  Usage: lightscan -t <target> [options]")
        print("         lightscan --auto <domain>")
        print(f"\n  \033[38;5;196mlightscan -h\033[0m  for help\n")
        sys.exit(0)

    if any(h in argv for h in ("-h", "--help", "-ha", "--help-all")):
        no_banner = "--no-banner" in argv
        if not no_banner:
            print_banner(no_quote=True)
        print_minimal_help()
        sys.exit(0)

    p    = build_parser()
    args = p.parse_args(argv)
    args.concurrency = _tune_concurrency(args.concurrency)

    target_actions = [
        getattr(args, 'scan', False),
        getattr(args, 'active', False),
        getattr(args, 'web_scan', None),
        getattr(args, 'brute', None),
        getattr(args, 'auto', None),
        getattr(args, 'dns', None),
        getattr(args, 'os_probe', None),
        getattr(args, 'traceroute', None),
    ]
    if not getattr(args, 'target', None) and not sys.stdin.isatty() and any(target_actions):
        args.target = "-"

    if getattr(args, 'output', None) == "-":
        from lightscan.core.reporter import Reporter
        Reporter.stdout_override = sys.stdout
        sys.stdout = sys.stderr

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print(f"\n\033[38;5;240m[!] Interrupted — checkpoint saved\033[0m")
    except TargetSpecError as exc:
        print(f"\n\033[38;5;208m[!] Invalid scan input: {exc}\033[0m", file=sys.stderr)
        sys.exit(2)
    except PermissionError as e:
        print(f"\n\033[38;5;208m[!] Permission denied: {e}")
        print("    Raw/packet scans require root. Try sudo or use --scan.\033[0m")
        sys.exit(1)

if __name__=="__main__": main()

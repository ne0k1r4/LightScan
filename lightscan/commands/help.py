"""Compact terminal help presentation."""
from __future__ import annotations

def print_minimal_help() -> None:
    """Print an animated, ultra-short terminal help guide."""
    import time
    import sys
    
    RED = "\033[38;5;196m"
    ORANGE = "\033[38;5;202m"
    YEL = "\033[38;5;220m"
    DIM = "\033[38;5;242m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    
    help_lines = [
        f"{RED}┌───\033[0m {BOLD}LIGHTSCAN HELP\033[0m {RED}" + "─" * 58 + f"\033[0m",
        f"  Usage: lightscan -t <target> [options]",
        f"         lightscan --auto <domain>",
        "",
        f"  Core Commands:",
        f"    {ORANGE}--auto <domain>{RESET}      Autonomous audit (recon → exploit → map)",
        f"    {ORANGE}--scan -t <target>{RESET}   Bounded streaming TCP discovery scan (top100)",
        f"    {ORANGE}--active -t <target>{RESET} Full active scan (probe → vuln check → pivot)",
        f"    {ORANGE}--web-scan <url>{RESET}     Web vulnerability audit directory/SQLi/CORS",
        f"    {ORANGE}--brute <proto>{RESET}      Credential brute-force (ssh, ftp, mysql...)",
        "",
        f"  Common Options:",
        f"    {ORANGE}-p <ports>{RESET}          Ports (e.g. 22,80,443 | 1-1024 | top100)",
        f"    {ORANGE}--max-rate <n>{RESET}      Cap TCP connection starts per second",
        f"    {ORANGE}--retry-jitter <0..1>{RESET} Randomize retry backoff (default: 0.15)",
        f"    {ORANGE}--per-host-concurrency{RESET}  Limit in-flight TCP jobs per host",
        f"    {ORANGE}--go-engine{RESET}         Use compiled Go TCP scanner (make go first)",
        f"    {ORANGE}--stream-open <path>{RESET} Stream open results as NDJSON",
        f"    {ORANGE}--metrics-out <path>{RESET}  Save comparable performance telemetry",
        f"    {ORANGE}--import-nmap-xml <path>{RESET} Import local Nmap OS/service evidence only",
        f"    {ORANGE}--os-evidence{RESET}       Infer OS family from existing service data only",
        f"    {ORANGE}--lua-script <check>{RESET} Run constrained safe Lua checks",
        f"    {ORANGE}--list-lua-scripts{RESET}  List bundled Lua checks without scanning",
        f"    {ORANGE}--cve{RESET}               Run legacy/template vulnerability checks",
        f"    {ORANGE}--stealth{RESET}           IDS evasion timing template + jitter",
        f"    {ORANGE}--format <fmt>{RESET}       Output: json, html, csv, xml, minimal",
        "",
        f"  Example:",
        f"    {YEL}lightscan --scan -t 192.0.2.10 -p 443 --lua-script http-security-headers{RESET}",
        f"    {YEL}lightscan --compare-metrics baseline.json candidate.json{RESET}",
        f"{RED}└" + "─" * 76 + f"\033[0m",
        ""
    ]
    
    is_tty = sys.stdout.isatty()
    for line in help_lines:
        print(line)
        if is_tty:
            time.sleep(0.012)

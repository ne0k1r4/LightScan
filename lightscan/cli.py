# lightscan v0.2.0 — async scanner with banner grabbing
# Light (Neok1ra)
from __future__ import annotations
import argparse
import asyncio
import sys
import time

from lightscan.core.engine import PhantomEngine
from lightscan.core.target import parse_targets, parse_ports
from lightscan.scan.portscan import build_scan_tasks


def build_parser():
    p = argparse.ArgumentParser(prog="lightscan",
        description="lightscan v0.2.0 — async TCP scanner + banner grab")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-p", "--ports", default="top100")
    p.add_argument("-c", "--concurrency", type=int, default=256)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main():
    args = build_parser().parse_args()
    hosts = parse_targets(args.target)
    ports = parse_ports(args.ports)
    print(f"[*] {len(hosts)} host(s) × {len(ports)} port(s) | concurrency={args.concurrency}")
    engine  = PhantomEngine(concurrency=args.concurrency, timeout=args.timeout, verbose=args.verbose)
    tasks   = build_scan_tasks(hosts, ports, args.timeout)
    results = asyncio.run(engine.run(tasks))
    print(f"\n[+] {len(results)} open ports found")
    for r in sorted(results, key=lambda x: x.port):
        print(f"  OPEN  {r.host}:{r.port:<6} {r.detail}")

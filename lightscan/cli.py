# lightscan v0.1.0 — basic tcp scanner
# Light (Neok1ra)
from __future__ import annotations
import argparse
import asyncio
import socket
import sys
import time

__version__ = "0.1.0"

TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]


async def tcp_connect(host: str, port: int, timeout: float) -> tuple[int, bool]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        return port, True
    except Exception:
        return port, False


async def scan(host: str, ports: list, concurrency: int, timeout: float):
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def _one(p):
        async with sem:
            return await tcp_connect(host, p, timeout)

    tasks = [asyncio.create_task(_one(p)) for p in ports]
    for i, coro in enumerate(asyncio.as_completed(tasks)):
        port, open_ = await coro
        print(f"\r[{i+1}/{len(ports)}]", end="", flush=True)
        if open_:
            results.append(port)
    print()
    return sorted(results)


def resolve_host(host: str) -> str:
    """resolve hostname to ip, handle both v4 and v6"""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"[-] could not resolve {host}: {e}")
        sys.exit(1)


def parse_ports(spec: str) -> list:
    if spec == "top20":
        return TOP_PORTS
    ports = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(part))
    return ports


def build_parser():
    p = argparse.ArgumentParser(prog="lightscan",
        description="lightscan v0.1.0 — async TCP port scanner")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-p", "--ports", default="top20")
    p.add_argument("-c", "--concurrency", type=int, default=100)
    p.add_argument("--timeout", type=float, default=1.0)
    return p


def main():
    args = build_parser().parse_args()
    ports = parse_ports(args.ports)
    print(f"[*] scanning {args.target} | {len(ports)} ports | concurrency={args.concurrency}")
    t0 = time.time()
    open_ports = asyncio.run(scan(args.target, ports, args.concurrency, args.timeout))
    elapsed = time.time() - t0
    print(f"\n[+] done in {elapsed:.2f}s")
    if open_ports:
        for p in open_ports:
            print(f"  OPEN  {args.target}:{p}")
    else:
        print("  no open ports found")


if __name__ == "__main__":
    main()

"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

@dataclass
class EvasionConfig:
    timing:         int   = 4
    min_rate:       float = 0.0
    max_rate:       float = 0.0

    ttl:            int   = 64
    fragment:       bool  = False
    bad_checksum:   bool  = False
    data_length:    int   = 0
    source_port:    int   = 0

    decoys:         int   = 0
    decoy_ips:      List[str] = field(default_factory=list)
    randomize:      bool  = True
    randomize_hosts:bool  = False

    jitter_pct:     float = 0.0

    def effective_interval(self, base_interval: float) -> float:
        if self.jitter_pct > 0:
            jitter = base_interval * self.jitter_pct * random.uniform(-1, 1)
            return max(0.0, base_interval + jitter)
        return base_interval

    def effective_ttl(self) -> int:
        if self.ttl == 0:
            return random.choice([64, 128, 255])
        return self.ttl

class RateLimiter:
    def __init__(self, rate: float):
        self._rate      = rate
        self._tokens    = rate
        self._last      = time.monotonic()
        self._interval  = 1.0 / rate if rate > 0 else 0.0

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
        self._last = now

    async def acquire(self):
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            sleep_time = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(sleep_time)

    def acquire_sync(self):
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            sleep_time = (1.0 - self._tokens) / self._rate
            time.sleep(sleep_time)

class ScanScheduler:
    def __init__(self, evasion: EvasionConfig):
        from lightscan.scan.rawscan import TIMING
        self.evasion = evasion
        self.tmpl    = TIMING[evasion.timing]

        rate = evasion.max_rate if evasion.max_rate > 0 else self.tmpl.max_rate
        self.limiter = RateLimiter(rate)
        self._sem    = asyncio.Semaphore(self.tmpl.parallelism)

    @property
    def timeout(self) -> float:
        return self.tmpl.timeout

    @property
    def retries(self) -> int:
        return self.tmpl.retries

    async def slot(self):
        await self.limiter.acquire()
        await self._sem.acquire()

    def release(self):
        self._sem.release()

    def order_ports(self, ports: List[int]) -> List[int]:
        result = list(ports)
        if self.evasion.randomize:
            random.shuffle(result)
        return result

    def order_hosts(self, hosts: List[str]) -> List[str]:
        result = list(hosts)
        if self.evasion.randomize_hosts:
            random.shuffle(result)
        return result

def parse_timing(spec: str) -> int:
    spec = spec.strip().upper()
    mapping = {
        "T0": 0, "PARANOID": 0,
        "T1": 1, "SNEAKY": 1,
        "T2": 2, "POLITE": 2,
        "T3": 3, "NORMAL": 3,
        "T4": 4, "AGGRESSIVE": 4,
        "T5": 5, "INSANE": 5,
    }
    if spec in mapping:
        return mapping[spec]
    try:
        v = int(spec.lstrip("T"))
        return max(0, min(5, v))
    except ValueError:
        return 4

def build_evasion(
    timing:          int   = 4,
    ttl:             int   = 64,
    fragment:        bool  = False,
    bad_checksum:    bool  = False,
    decoys:          int   = 0,
    decoy_ips:       Optional[List[str]] = None,
    source_port:     int   = 0,
    data_length:     int   = 0,
    randomize:       bool  = True,
    randomize_hosts: bool  = False,
    jitter:          float = 0.0,
    min_rate:        float = 0.0,
    max_rate:        float = 0.0,
) -> EvasionConfig:
    return EvasionConfig(
        timing=timing, ttl=ttl, fragment=fragment,
        bad_checksum=bad_checksum, decoys=decoys,
        decoy_ips=decoy_ips or [], source_port=source_port,
        data_length=data_length, randomize=randomize,
        randomize_hosts=randomize_hosts, jitter_pct=jitter,
        min_rate=min_rate, max_rate=max_rate,
    )

def timing_summary(t: int) -> str:
    from lightscan.scan.rawscan import TIMING
    tmpl = TIMING[t]
    return (f"T{t} {tmpl.name}: timeout={tmpl.timeout}s "
            f"rate={tmpl.min_rate:.0f}-{tmpl.max_rate:.0f}pps "
            f"parallelism={tmpl.parallelism} retries={tmpl.retries}")

def print_timing_table():
    from lightscan.scan.rawscan import TIMING
    print("\n\033[38;5;196m[TIMING]\033[0m Available timing templates:\n")
    for i, tmpl in TIMING.items():
        print(f"  T{i}  {tmpl.name:<12} "
              f"timeout={tmpl.timeout:>6.1f}s  "
              f"rate={tmpl.min_rate:>6.0f}-{tmpl.max_rate:>6.0f} pps  "
              f"parallel={tmpl.parallelism:>4}  "
              f"retries={tmpl.retries}")
    print()

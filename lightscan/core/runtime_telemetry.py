"""
LightScan
Developer: Light (Neok1ra)
"""
from __future__ import annotations

import os
import resource
from dataclasses import asdict, dataclass
from pathlib import Path

@dataclass(frozen=True)
class RuntimeSnapshot:

    open_file_descriptors: int | None
    fd_soft_limit: int | None
    fd_hard_limit: int | None
    max_rss_kib: int | None

    def to_dict(self) -> dict[str, int | None]:
        return asdict(self)

def capture_runtime_snapshot() -> RuntimeSnapshot:
    open_fds: int | None = None
    proc_fd = Path("/proc/self/fd")
    try:
        open_fds = len(list(proc_fd.iterdir()))
    except OSError:
        pass

    soft_limit: int | None = None
    hard_limit: int | None = None
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        soft_limit = None if soft == resource.RLIM_INFINITY else int(soft)
        hard_limit = None if hard == resource.RLIM_INFINITY else int(hard)
    except (AttributeError, OSError, ValueError):
        pass

    max_rss: int | None = None
    try:
        max_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (AttributeError, OSError):
        pass

    return RuntimeSnapshot(
        open_file_descriptors=open_fds,
        fd_soft_limit=soft_limit,
        fd_hard_limit=hard_limit,
        max_rss_kib=max_rss,
    )

def resource_delta(
    started: RuntimeSnapshot,
    finished: RuntimeSnapshot,
) -> dict[str, int | None]:
    delta_fds: int | None = None
    if started.open_file_descriptors is not None and finished.open_file_descriptors is not None:
        delta_fds = finished.open_file_descriptors - started.open_file_descriptors
    return {
        "open_fds_start": started.open_file_descriptors,
        "open_fds_end": finished.open_file_descriptors,
        "open_fds_delta": delta_fds,
        "fd_soft_limit": finished.fd_soft_limit,
        "fd_hard_limit": finished.fd_hard_limit,
        "max_rss_kib": finished.max_rss_kib,
    }

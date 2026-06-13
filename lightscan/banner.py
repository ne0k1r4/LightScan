"""
banner.py — startup banner + runtime context line
Light (Neok1ra)

quotes rotate randomly every run so it doesn't feel like the same thing
every time. root status + python version print because i've debugged
"why isn't my raw scan working" too many times before realising i wasn't root.
"""
from __future__ import annotations
import os
import random
import shutil
import sys

VERSION = "2.0.0-PHANTOM"
AUTHOR  = "Light"
ALIAS   = "Neok1ra"

_ART = (
    "\033[38;5;196m"
    "\n\u2588\u2588\u2557     \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557  \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2557   \u2588\u2588\u2557"
    "\n\u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2551  \u2588\u2588\u2551\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551"
    "\n\u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551      \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551"
    "\n\u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551   \u2588\u2588\u2551   \u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551      \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551"
    "\n\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551"
    "\n\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d   \u255a\u2550\u255d   \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d"
    "\033[0m"
)

_QUOTES = [
    '"This world is rotten, and those who are making it rot deserve to die."',
    '"I am justice." -- and the packets are my pen.',
    '"The real power is not in the exploit. It is in knowing exactly where to look."',
    '"If you cannot find the open port, you are not scanning hard enough."',
    '"I will take this network... and eat it!"',
    '"In this world, those with the best recon make the rules."',
    '"There is no such thing as an impenetrable network. Only undiscovered entry points."',
]


def _term_width() -> int:
    try:
        return min(shutil.get_terminal_size(fallback=(80, 24)).columns, 90)
    except Exception:
        return 72


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


def print_banner(no_quote: bool = False) -> None:
    """Print the startup banner with runtime context.

    no_quote=True skips the rotating quote — for JSON/minimal output modes.
    """
    width = _term_width()
    sep   = "\033[38;5;196m" + "\u2500" * width + "\033[0m"

    print(_ART)
    print(
        f"  \033[38;5;240mv{VERSION}  \u00b7  by "
        f"\033[38;5;196m{AUTHOR}\033[38;5;240m ({ALIAS})"
        f"  \u00b7  Async Network Recon & Attack Framework\033[0m"
    )

    # runtime info — shown dim so it doesn't compete with the banner
    # this line has saved me from "why is raw scan broken" at least 10 times
    py   = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    root_str = (
        "\033[38;5;196mroot\033[38;5;240m"
        if _is_root() else
        "\033[38;5;208mno-root\033[38;5;240m (raw/packet scans will fail)\033[0m"
    )
    print(f"  \033[38;5;240mpython {py}  \u00b7  {root_str}  \u00b7  pid {os.getpid()}\033[0m")

    if not no_quote:
        print(f"\n  \033[38;5;238m{random.choice(_QUOTES)}\033[0m")

    print(sep + "\n")

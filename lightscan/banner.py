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

    lines = [
        "\u2588\u2588\u2557     \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557  \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2557   \u2588\u2588\u2557",
        "\u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2551  \u2588\u2588\u2551\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551",
        "\u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551      \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551",
        "\u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551   \u2588\u2588\u2551   \u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551      \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551",
        "\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551",
        "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d   \u255a\u2550\u255d   \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d"
    ]

    is_tty = sys.stdout.isatty()

    if is_tty and not no_quote:
        # Cyberpunk glitchy decrypt animation
        import time
        glitch_chars = "01$#@%&?!=[]{}<>+/\\*^~X"
        steps = 8
        sys.stdout.write("\033[?25l")  # Hide cursor
        sys.stdout.flush()
        try:
            for step in range(steps):
                sys.stdout.write("\r")
                if step > 0:
                    sys.stdout.write(f"\033[{len(lines) + 1}A")
                sys.stdout.write("\n")
                for idx, line in enumerate(lines):
                    # Higher step = higher probability of correct character
                    real_ratio = step / (steps - 1)
                    animated_line = []
                    for char in line:
                        if char.isspace():
                            animated_line.append(char)
                        elif random.random() < real_ratio:
                            animated_line.append(char)
                        else:
                            animated_line.append(random.choice(glitch_chars))
                    
                    # Gradient color progression (grey -> deep red -> neon red)
                    if step < 2:
                        color = 236
                    elif step < 4:
                        color = 88
                    elif step < 6:
                        color = 124
                    else:
                        color = 196
                    
                    sys.stdout.write(f"\033[38;5;{color}m" + "".join(animated_line) + "\033[0m\n")
                sys.stdout.flush()
                time.sleep(0.04)
            # Pull cursor back up to redraw the static banner cleanly
            sys.stdout.write(f"\033[{len(lines) + 1}A")
        finally:
            sys.stdout.write("\033[?25h")  # Show cursor
            sys.stdout.flush()

    print(_ART)

    if not no_quote:
        print(f"\n  \033[38;5;238m{random.choice(_QUOTES)}\033[0m")

    print(sep + "\n")

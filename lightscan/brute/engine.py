# brute/engine.py — v0.3 credential brute force engine
# Light (Neok1ra)
#
# supports SSH and FTP for now — more protocols coming
# uses asyncio + thread executor for blocking ssh/ftp libs
from __future__ import annotations
import asyncio
from lightscan.core.checkpoint import Checkpoint


class BruteEngine:
    def __init__(self, protocol: str, host: str, port: int,
                 users: list, passwords: list,
                 concurrency: int = 10, timeout: float = 5.0,
                 checkpoint: Checkpoint | None = None):
        self.protocol    = protocol
        self.host        = host
        self.port        = port
        self.users       = users
        self.passwords   = passwords
        self.concurrency = concurrency
        self.timeout     = timeout
        self.cp          = checkpoint or Checkpoint()
        self.found       = []

    async def run(self) -> list:
        sem   = asyncio.Semaphore(self.concurrency)
        tasks = []
        for user in self.users:
            for pw in self.passwords:
                key = f"{user}:{pw}"
                if self.cp.was_tried(key):
                    continue
                tasks.append(self._try(sem, user, pw))

        print(f"[BRUTE] {self.protocol.upper()} | {self.host}:{self.port} | "
              f"{len(tasks)} combinations")
        await asyncio.gather(*tasks)
        return self.found

    async def _try(self, sem, user: str, pw: str):
        async with sem:
            key = f"{user}:{pw}"
            try:
                ok = await asyncio.wait_for(
                    asyncio.get_running_loop().run_in_executor(
                        None, self._attempt, user, pw),
                    timeout=self.timeout)
                if ok:
                    print(f"\n[+] FOUND {self.protocol.upper()} {self.host} — {user}:{pw}")
                    self.cp.mark_found({"user": user, "pw": pw, "host": self.host})
                    self.found.append((user, pw))
            except Exception:
                pass
            finally:
                self.cp.mark_tried(key)

    def _attempt(self, user: str, pw: str) -> bool:
        """override per protocol — sync blocking call"""
        return False

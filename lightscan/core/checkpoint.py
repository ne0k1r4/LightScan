# core/checkpoint.py — v0.3 brute checkpoint (no lock yet — added later)
# Light
from __future__ import annotations
import json
import os
import time


class Checkpoint:
    """save/resume brute force progress.
    
    stores tried credentials so a crash or ctrl-c doesn't lose progress.
    simple json file — nothing fancy.
    """

    def __init__(self, path=".lightscan_cp.json"):
        self.path = path
        self._state = {"tried": [], "found": [], "meta": {"started": time.time()}}
        self._tried_set = set()
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self._state = json.load(f)
                self._tried_set = set(self._state.get("tried", []))
                print(f"[RESUME] Loaded checkpoint: {len(self._tried_set)} tried, "
                      f"{len(self._state.get('found', []))} found")
            except Exception:
                pass

    def _save(self):
        # convert set back to list for json — sets aren't serializable
        self._state["tried"] = list(self._tried_set)
        with open(self.path, "w") as f:
            json.dump(self._state, f)

    def mark_tried(self, key: str):
        self._tried_set.add(key)
        if len(self._tried_set) % 50 == 0:
            self._save()

    def was_tried(self, key: str) -> bool:
        return key in self._tried_set

    def mark_found(self, credential: dict):
        self._state["found"].append(credential)
        self._save()

    def clear(self):
        # NOTE: no lock here — race condition if called while brute is running
        # fixed in a later commit
        self._state = {"tried": [], "found": [], "meta": {"started": time.time()}}
        self._tried_set.clear()
        if os.path.exists(self.path):
            os.remove(self.path)

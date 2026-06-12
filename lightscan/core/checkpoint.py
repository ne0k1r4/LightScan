"""
Checkpoint — lets long brute-force runs survive interruptions.

Writes a .lightscan_cp.json file every 100 attempts so you can
resume from where you left off with --resume. Also tracks locked
accounts so the engine stops hammering them once lockout is detected.
"""
import json
import os
import time
from threading import Lock

class Checkpoint:
    def __init__(self, path=".lightscan_cp.json", save_every=100):
        self.path = path
        self.save_every = save_every
        self._lock = Lock()
        self._state = self._load()
        self._dirty = 0
        self._tried_set = set(tuple(x) for x in self._state["tried"])
        self._locked_set = set(self._state["locked"])

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    data = json.load(f)
                tried = len(data.get("tried", []))
                found = len(data.get("found", []))
                print(f"\033[38;5;196m[RESUME]\033[0m Loaded checkpoint: {tried} tried, {found} found")
                return data
            except Exception:
                pass
        return {
            "tried": [],
            "found": [],
            "locked": [],
            "scanned": [],
            "meta": {"started": time.time()}
        }

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self._state, f, indent=2)
        except Exception:
            pass

    def flush(self):
        with self._lock:
            self._save()

    def mark_tried(self, user, passwd):
        with self._lock:
            pair = (user, passwd)
            if pair not in self._tried_set:
                self._tried_set.add(pair)
                self._state["tried"].append([user, passwd])
                if len(self._state["tried"]) > 50000:
                    self._state["tried"] = self._state["tried"][-50000:]
                    self._tried_set = set(tuple(x) for x in self._state["tried"])
                self._dirty += 1
                if self._dirty >= self.save_every:
                    self._save()
                    self._dirty = 0

    def already_tried(self, user, passwd):
        with self._lock:
            return (user, passwd) in self._tried_set

    def add_found(self, entry):
        with self._lock:
            self._state["found"].append(entry)
            self._save()

    def mark_locked(self, user):
        with self._lock:
            if user not in self._locked_set:
                self._locked_set.add(user)
                self._state["locked"].append(user)

    def is_locked(self, user):
        with self._lock:
            return user in self._locked_set

    def get_found(self):
        return self._state.get("found", [])

    def set_target(self, t):
        self._state["meta"]["target"] = t
        self._save()

    def clear(self):
        self._state = {
            "tried": [],
            "found": [],
            "locked": [],
            "scanned": [],
            "meta": {"started": time.time()}
        }
        self._tried_set.clear()
        self._locked_set.clear()
        if os.path.exists(self.path):
            os.remove(self.path)
        print("\033[38;5;240m[*] Checkpoint cleared\033[0m")

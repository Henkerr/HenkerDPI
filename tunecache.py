"""Per-network memory of which bypass strategy was measured to work.

Both platforms measure a strategy on first sight of a network and reuse it
afterwards, but they measure different things — Windows picks a (decoy, split)
pair, macOS picks a framing technique — so the payload is left opaque and only
the bookkeeping lives here: keyed by network, expiring, and bounded.

A failed measurement is remembered too, but briefly. Re-scanning every launch on
a line where nothing works would make the app feel broken; never re-scanning
would mean an ISP that changed its rules stays defeated forever.
"""

import json
import os
import time

CACHE_TTL = 7 * 24 * 3600
CACHE_TTL_FAILED = 3600
MAX_ENTRIES = 20


class TuneCache:
    def __init__(self, path: str, ttl: int = CACHE_TTL,
                 ttl_failed: int = CACHE_TTL_FAILED):
        self.path = path
        self.ttl = ttl
        self.ttl_failed = ttl_failed

    def _load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, cache: dict) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def get(self, signature: str):
        """The stored payload for this network, or None if absent/expired."""
        entry = self._load().get(signature)
        if not isinstance(entry, dict):
            return None
        ttl = self.ttl if entry.get("ok") else self.ttl_failed
        if time.time() - entry.get("ts", 0) > ttl:
            return None
        payload = entry.get("payload")
        return payload if isinstance(payload, dict) else None

    def put(self, signature: str, payload: dict, ok: bool) -> None:
        cache = self._load()
        cache[signature] = {"payload": payload, "ok": ok, "ts": int(time.time())}
        if len(cache) > MAX_ENTRIES:
            for key in sorted(cache,
                              key=lambda k: cache[k].get("ts", 0)
                              )[:-MAX_ENTRIES]:
                cache.pop(key, None)
        self._save(cache)

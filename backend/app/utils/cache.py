"""
In-memory TTL cache for DNS, WHOIS, and IP reputation results.
"""

from collections import OrderedDict
from threading import RLock
import time
from typing import Any, Optional


DEFAULT_MAX_ENTRIES = 512


class TTLCache:
    """Bounded in-memory cache with per-entry time-to-live expiry."""

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES):
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self.max_entries = max_entries
        self._store: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = RLock()

    def get(self, key: str) -> Optional[Any]:
        """Return cached value or None if missing/expired."""
        now = time.time()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expiry = entry
            if now >= expiry:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            return value

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Store value with TTL expiry.

        ``None`` is treated as a cache miss by the public API, so it is not
        stored. Non-positive TTL values also remove any existing value.
        """
        now = time.time()
        with self._lock:
            if value is None or ttl_seconds <= 0:
                self._store.pop(key, None)
                return

            self._store[key] = (value, now + ttl_seconds)
            self._store.move_to_end(key)
            self._clear_expired_locked(now)
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)

    def clear_expired(self) -> int:
        """Remove all expired entries, return count removed."""
        now = time.time()
        with self._lock:
            return self._clear_expired_locked(now)

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._store.clear()

    def _clear_expired_locked(self, now: float) -> int:
        expired = [k for k, (_, exp) in self._store.items() if now >= exp]
        for k in expired:
            del self._store[k]
        return len(expired)


_cache = TTLCache()


def cache_get(key: str) -> Optional[Any]:
    return _cache.get(key)


def cache_set(key: str, value: Any, ttl: int) -> None:
    _cache.set(key, value, ttl)

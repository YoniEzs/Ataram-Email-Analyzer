"""
In-memory TTL cache for DNS, WHOIS, and IP reputation results
"""

import threading
import time
from collections import OrderedDict
from typing import Any, Optional

# Default ceiling on stored entries. The cache is keyed by domain/IP taken from
# untrusted input, so without a bound a stream of unique lookups grows it until
# the worker is OOM-killed. Overridden from config at app startup.
DEFAULT_MAX_ENTRIES = 5000

# Companion byte ceiling. Entry count alone does not bound memory: one DNS
# answer can carry 20 TXT records of 4KB each, so 5,000 entries is not 5,000
# small things. 32MB is generous for a lookup cache and hard-caps the worst case.
DEFAULT_MAX_BYTES = 32 * 1024 * 1024


class _Miss:
    """Sentinel distinguishing 'not cached' from 'cached the value None'."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return '<cache miss>'

    def __bool__(self) -> bool:
        return False


MISS = _Miss()


class TTLCache:
    """
    Bounded in-memory cache with per-entry time-to-live expiry.

    Eviction is least-recently-used once `max_entries` is reached, so a burst of
    one-off lookups cannot push out the entries that are actually being reused.
    Access is lock-guarded: gunicorn sync workers are single-threaded, but the
    cache is also reachable from the dev server's threaded mode.
    """

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES,
                 max_bytes: int = DEFAULT_MAX_BYTES):
        self._store: "OrderedDict[str, tuple]" = OrderedDict()
        self._lock = threading.Lock()
        self._max_entries = max(1, int(max_entries))
        self._max_bytes = max(1024, int(max_bytes))
        self._bytes = 0

    @property
    def max_entries(self) -> int:
        return self._max_entries

    def configure(self, max_entries: int, max_bytes: int = None) -> None:
        """Resize the cache, evicting anything over the new ceiling."""
        with self._lock:
            self._max_entries = max(1, int(max_entries))
            if max_bytes is not None:
                self._max_bytes = max(1024, int(max_bytes))
            while len(self._store) > self._max_entries or self._bytes > self._max_bytes:
                if not self._store:
                    break
                _k, (_v, _e, size) = self._store.popitem(last=False)
                self._bytes -= size

    def get(self, key: str, default: Any = None) -> Optional[Any]:
        """Return the cached value, or `default` if missing or expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return default
            value, expiry, size = entry
            if time.time() > expiry:
                del self._store[key]
                self._bytes -= size
                return default
            # Refresh recency so the LRU order reflects actual use.
            self._store.move_to_end(key)
            return value

    @staticmethod
    def _rough_size(value: Any) -> int:
        """
        Cheap upper-ish estimate of what an entry costs.

        Bounding by entry COUNT alone is not enough: a single DNS answer can
        hold 20 TXT records of 4KB each, so 5,000 "entries" is not a bounded
        amount of memory. This is deliberately approximate — it only has to
        stop one pathological entry from being counted the same as a null.
        """
        try:
            if value is None:
                return 16
            if isinstance(value, str):
                return len(value) + 48
            if isinstance(value, (bytes, bytearray)):
                return len(value) + 32
            if isinstance(value, (list, tuple, set)):
                return sum(TTLCache._rough_size(v) for v in value) + 56
            if isinstance(value, dict):
                return sum(
                    len(str(k)) + TTLCache._rough_size(v) for k, v in value.items()
                ) + 64
            return 64
        except Exception:
            return 64

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Store value with TTL expiry, evicting the least recently used if full."""
        size = self._rough_size(value) + len(key)
        with self._lock:
            if key in self._store:
                _old_value, _expiry, old_size = self._store[key]
                self._bytes -= old_size
                self._store.move_to_end(key)
            self._store[key] = (value, time.time() + ttl_seconds, size)
            self._bytes += size
            while len(self._store) > self._max_entries or self._bytes > self._max_bytes:
                if not self._store:
                    break
                _evicted_key, (_v, _e, evicted_size) = self._store.popitem(last=False)
                self._bytes -= evicted_size

    def clear_expired(self) -> int:
        """Remove all expired entries, return count removed"""
        with self._lock:
            now = time.time()
            expired = [k for k, (_v, exp, _s) in list(self._store.items()) if now > exp]
            for k in expired:
                self._bytes -= self._store[k][2]
                del self._store[k]
            return len(expired)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._bytes = 0

    def nbytes(self) -> int:
        with self._lock:
            return self._bytes

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


_cache = TTLCache()


def cache_get(key: str, default: Any = None) -> Optional[Any]:
    """
    Read a cached value.

    Pass `default=MISS` to tell a cached `None` (a negative result worth
    honouring) apart from an absent key.
    """
    return _cache.get(key, default)


def cache_set(key: str, value: Any, ttl: int) -> None:
    _cache.set(key, value, ttl)


def cache_configure(max_entries: int, max_bytes: int = None) -> None:
    _cache.configure(max_entries, max_bytes)


def cache_nbytes() -> int:
    return _cache.nbytes()


def cache_size() -> int:
    return len(_cache)


def cache_clear() -> None:
    _cache.clear()

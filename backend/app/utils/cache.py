"""
TTL cache for DNS, WHOIS, and IP reputation results.

Backend is chosen at import time: Redis when CACHE_REDIS_URL / REDIS_URL is
set (shared across gunicorn workers), otherwise a bounded in-memory cache.
Redis failures degrade to cache misses — they never break an analysis.
"""

import json
import logging
import os
from collections import OrderedDict
from threading import RLock
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

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


class RedisCache:
    """Redis-backed cache with the same get/set semantics as TTLCache.

    Values are stored as JSON (all cached payloads are plain dicts/lists/
    strings). Connection or serialization errors are logged and treated as
    cache misses so a Redis outage can't take analyses down.
    """

    _PREFIX = 'email-analyzer:'

    def __init__(self, url: str):
        import redis  # deferred so the package is only needed when enabled

        self._client = redis.Redis.from_url(
            url, socket_timeout=2, socket_connect_timeout=2
        )

    def get(self, key: str) -> Optional[Any]:
        try:
            raw = self._client.get(self._PREFIX + key)
            # redis-py types get() as possibly-awaitable; the sync client
            # always returns bytes/None here.
            return json.loads(raw) if raw is not None else None  # type: ignore[arg-type]
        except Exception as e:
            logger.warning(f"[RedisCache] get failed for {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        try:
            if value is None or ttl_seconds <= 0:
                self._client.delete(self._PREFIX + key)
                return
            self._client.setex(self._PREFIX + key, ttl_seconds, json.dumps(value))
        except Exception as e:
            logger.warning(f"[RedisCache] set failed for {key}: {e}")

    def clear(self) -> None:
        try:
            keys = list(self._client.scan_iter(self._PREFIX + '*'))
            if keys:
                self._client.delete(*keys)
        except Exception as e:
            logger.warning(f"[RedisCache] clear failed: {e}")


def _create_cache():
    url = os.environ.get('CACHE_REDIS_URL') or os.environ.get('REDIS_URL')
    if url:
        try:
            return RedisCache(url)
        except Exception as e:
            logger.warning(
                f"[cache] Redis backend unavailable ({e}); "
                "falling back to in-memory cache"
            )
    return TTLCache()


_cache = _create_cache()


def cache_get(key: str) -> Optional[Any]:
    return _cache.get(key)


def cache_set(key: str, value: Any, ttl: int) -> None:
    _cache.set(key, value, ttl)

"""
Tests for in-memory TTL cache utility.
"""

import pytest

from app.utils import cache as cache_module


def _set_time(monkeypatch, now_holder):
    monkeypatch.setattr(cache_module.time, "time", lambda: now_holder["value"])


def _reset_cache():
    cache_module._cache.clear()


def test_cache_hit_before_expiry(monkeypatch):
    _reset_cache()
    now = {"value": 1_000.0}
    _set_time(monkeypatch, now)

    cache_module.cache_set("dns:example.com", ["v=spf1 -all"], ttl=60)
    assert cache_module.cache_get("dns:example.com") == ["v=spf1 -all"]


def test_cache_expired_entry_returns_none(monkeypatch):
    _reset_cache()
    now = {"value": 2_000.0}
    _set_time(monkeypatch, now)

    cache_module.cache_set("ip:1.1.1.1", {"score": 0}, ttl=5)
    now["value"] = 2_005.0

    assert cache_module.cache_get("ip:1.1.1.1") is None


def test_clear_expired_removes_only_expired_entries(monkeypatch):
    _reset_cache()
    now = {"value": 3_000.0}
    _set_time(monkeypatch, now)

    cache_module.cache_set("fresh", "ok", ttl=30)
    cache_module.cache_set("stale", "old", ttl=5)
    now["value"] = 3_010.0

    removed_count = cache_module._cache.clear_expired()

    assert removed_count == 1
    assert cache_module.cache_get("fresh") == "ok"
    assert cache_module.cache_get("stale") is None


def test_cache_uses_lru_eviction_when_bounded(monkeypatch):
    now = {"value": 4_000.0}
    _set_time(monkeypatch, now)
    cache = cache_module.TTLCache(max_entries=2)

    cache.set("first", "1", ttl_seconds=60)
    cache.set("second", "2", ttl_seconds=60)
    assert cache.get("first") == "1"

    cache.set("third", "3", ttl_seconds=60)

    assert cache.get("first") == "1"
    assert cache.get("second") is None
    assert cache.get("third") == "3"


def test_set_discards_none_and_non_positive_ttl_values(monkeypatch):
    now = {"value": 5_000.0}
    _set_time(monkeypatch, now)
    cache = cache_module.TTLCache(max_entries=2)

    cache.set("none-value", None, ttl_seconds=60)
    cache.set("expired-immediately", "value", ttl_seconds=0)
    cache.set("kept", "value", ttl_seconds=60)
    cache.set("kept", "replacement", ttl_seconds=-1)

    assert cache.get("none-value") is None
    assert cache.get("expired-immediately") is None
    assert cache.get("kept") is None
    assert len(cache._store) == 0


def test_cache_rejects_invalid_capacity():
    with pytest.raises(ValueError, match="max_entries"):
        cache_module.TTLCache(max_entries=0)

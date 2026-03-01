"""Tests for the Redis query cache (engine/core/cache.py).

Covers:
- QueryCache get/set/invalidate/invalidate_pattern/flush/close
- Graceful degradation when Redis is unavailable
- _make_cache_key determinism
- @cached decorator (hit, miss, bypass)
- get_cache singleton
- JSON serialization edge cases
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.core.cache import (
    QueryCache,
    _make_cache_key,
    cached,
    get_cache,
)


# ── Fixtures ─────────────────────────────────────────────────────────────


class FakeRedis:
    """Minimal async Redis mock for testing."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._ttls: dict[str, int] = {}

    async def ping(self):
        return True

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value
        if ex:
            self._ttls[key] = ex

    async def delete(self, *keys: str) -> int:
        count = 0
        for key in keys:
            if key in self._store:
                del self._store[key]
                count += 1
        return count

    async def scan_iter(self, match: str = "*", count: int = 100):
        import fnmatch
        for key in list(self._store.keys()):
            if fnmatch.fnmatch(key, match):
                yield key

    async def info(self, section: str = "") -> dict:
        if section == "stats":
            return {"keyspace_hits": 42, "keyspace_misses": 7}
        if section == "clients":
            return {"connected_clients": 1}
        return {}

    async def close(self):
        self._store.clear()


@pytest.fixture
def fake_redis():
    return FakeRedis()


@pytest.fixture
def cache_with_redis(fake_redis):
    """Return a QueryCache with a pre-attached fake Redis client."""
    qc = QueryCache.__new__(QueryCache)
    qc._url = "redis://localhost:6379/0"
    qc._prefix = "zc"
    qc._client = fake_redis
    qc._enabled = True
    return qc


@pytest.fixture
def cache_disabled():
    """Return a QueryCache with Redis disabled."""
    qc = QueryCache.__new__(QueryCache)
    qc._url = "redis://localhost:6379/0"
    qc._prefix = "zc"
    qc._client = None
    qc._enabled = False
    return qc


# ── QueryCache core operations ───────────────────────────────────────────


class TestQueryCacheCore:
    """Test get/set/invalidate operations."""

    @pytest.mark.asyncio
    async def test_set_and_get(self, cache_with_redis: QueryCache):
        await cache_with_redis.set("key1", {"foo": "bar"}, ttl=60)
        result = await cache_with_redis.get("key1")
        assert result == {"foo": "bar"}

    @pytest.mark.asyncio
    async def test_get_miss_returns_none(self, cache_with_redis: QueryCache):
        result = await cache_with_redis.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalidate(self, cache_with_redis: QueryCache):
        await cache_with_redis.set("key2", "value")
        await cache_with_redis.invalidate("key2")
        result = await cache_with_redis.get("key2")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalidate_pattern(self, cache_with_redis: QueryCache, fake_redis: FakeRedis):
        await cache_with_redis.set("prefix:a", 1)
        await cache_with_redis.set("prefix:b", 2)
        await cache_with_redis.set("other:c", 3)
        deleted = await cache_with_redis.invalidate_pattern("prefix:*")
        assert deleted == 2
        assert await cache_with_redis.get("other:c") == 3

    @pytest.mark.asyncio
    async def test_flush(self, cache_with_redis: QueryCache):
        await cache_with_redis.set("a", 1)
        await cache_with_redis.set("b", 2)
        await cache_with_redis.flush()
        assert await cache_with_redis.get("a") is None
        assert await cache_with_redis.get("b") is None

    @pytest.mark.asyncio
    async def test_close(self, cache_with_redis: QueryCache, fake_redis: FakeRedis):
        await cache_with_redis.close()
        assert cache_with_redis._client is None

    @pytest.mark.asyncio
    async def test_stats(self, cache_with_redis: QueryCache):
        stats = await cache_with_redis.stats()
        assert stats["enabled"] is True
        assert stats["hits"] == 42
        assert stats["misses"] == 7

    @pytest.mark.asyncio
    async def test_set_serializes_datetime(self, cache_with_redis: QueryCache, fake_redis: FakeRedis):
        """Datetimes should be serialized via default=str."""
        from datetime import datetime, timezone

        data = {"ts": datetime(2025, 1, 1, tzinfo=timezone.utc)}
        await cache_with_redis.set("dt_key", data)
        raw = fake_redis._store.get("zc:dt_key")
        assert raw is not None
        parsed = json.loads(raw)
        assert "2025" in parsed["ts"]

    @pytest.mark.asyncio
    async def test_set_with_default_ttl(self, cache_with_redis: QueryCache, fake_redis: FakeRedis):
        await cache_with_redis.set("ttl_key", "val")
        assert fake_redis._ttls.get("zc:ttl_key") == 300  # default TTL


# ── Graceful degradation ────────────────────────────────────────────────


class TestCacheDisabled:
    """Test behavior when Redis is unavailable."""

    @pytest.mark.asyncio
    async def test_get_returns_none(self, cache_disabled: QueryCache):
        result = await cache_disabled.get("anything")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_is_noop(self, cache_disabled: QueryCache):
        await cache_disabled.set("key", "value")
        # Should not raise

    @pytest.mark.asyncio
    async def test_invalidate_is_noop(self, cache_disabled: QueryCache):
        await cache_disabled.invalidate("key")

    @pytest.mark.asyncio
    async def test_invalidate_pattern_returns_zero(self, cache_disabled: QueryCache):
        count = await cache_disabled.invalidate_pattern("*")
        assert count == 0

    @pytest.mark.asyncio
    async def test_stats_returns_disabled(self, cache_disabled: QueryCache):
        stats = await cache_disabled.stats()
        assert stats == {"enabled": False}


# ── Cache key generation ─────────────────────────────────────────────────


class TestCacheKeyGeneration:
    """Test _make_cache_key determinism and uniqueness."""

    def test_same_args_same_key(self):
        k1 = _make_cache_key("prefix", ("a", "b"), {"x": 1})
        k2 = _make_cache_key("prefix", ("a", "b"), {"x": 1})
        assert k1 == k2

    def test_different_args_different_key(self):
        k1 = _make_cache_key("prefix", ("a",), {})
        k2 = _make_cache_key("prefix", ("b",), {})
        assert k1 != k2

    def test_different_prefix_different_key(self):
        k1 = _make_cache_key("alpha", ("a",), {})
        k2 = _make_cache_key("beta", ("a",), {})
        assert k1 != k2

    def test_kwarg_order_independent(self):
        k1 = _make_cache_key("p", (), {"a": 1, "b": 2})
        k2 = _make_cache_key("p", (), {"b": 2, "a": 1})
        assert k1 == k2

    def test_key_format(self):
        key = _make_cache_key("test", ("arg1",), {"k": "v"})
        assert key.startswith("test:")
        # hash portion is 12 chars
        assert len(key.split(":")[1]) == 12


# ── @cached decorator ───────────────────────────────────────────────────


class TestCachedDecorator:
    """Test the @cached decorator."""

    @pytest.mark.asyncio
    async def test_cache_miss_calls_function(self):
        call_count = 0

        @cached(ttl=60, prefix="test_fn")
        async def my_fn(x: int) -> dict:
            nonlocal call_count
            call_count += 1
            return {"result": x * 2}

        # Patch get_cache to return a disabled cache (always miss)
        with patch("engine.core.cache.get_cache") as mock_gc:
            disabled = QueryCache.__new__(QueryCache)
            disabled._url = ""
            disabled._prefix = "zc"
            disabled._client = None
            disabled._enabled = False
            mock_gc.return_value = disabled

            result = await my_fn(5)
            assert result == {"result": 10}
            assert call_count == 1

    @pytest.mark.asyncio
    async def test_cache_hit_skips_function(self, cache_with_redis: QueryCache):
        call_count = 0

        @cached(ttl=60, prefix="test_hit")
        async def my_fn(x: int) -> dict:
            nonlocal call_count
            call_count += 1
            return {"result": x * 2}

        with patch("engine.core.cache.get_cache", return_value=cache_with_redis):
            # First call — cache miss
            result1 = await my_fn(5)
            assert result1 == {"result": 10}
            assert call_count == 1

            # Second call — cache hit
            result2 = await my_fn(5)
            assert result2 == {"result": 10}
            assert call_count == 1  # Not called again


# ── get_cache singleton ──────────────────────────────────────────────────


class TestGetCacheSingleton:
    """Test the get_cache() singleton factory."""

    def test_returns_query_cache_instance(self):
        with patch("engine.core.cache._cache_instance", None):
            with patch("engine.core.cache.get_settings") as mock_settings:
                mock_settings.return_value = MagicMock(redis_url="redis://localhost:6379/0")
                cache = get_cache()
                assert isinstance(cache, QueryCache)

    def test_returns_same_instance(self):
        with patch("engine.core.cache._cache_instance", None):
            with patch("engine.core.cache.get_settings") as mock_settings:
                mock_settings.return_value = MagicMock(redis_url="redis://localhost:6379/0")
                c1 = get_cache()
                # Manually set _cache_instance to c1 for second call
                with patch("engine.core.cache._cache_instance", c1):
                    c2 = get_cache()
                    assert c2 is c1

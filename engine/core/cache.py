"""Redis-backed query cache for expensive API operations.

Provides transparent caching for scan results, analytics aggregations,
compliance reports, and other expensive database queries.

Usage:
    from engine.core.cache import QueryCache, cached

    cache = QueryCache()

    # Decorator-based caching
    @cached(ttl=300, prefix="audit-summary")
    async def get_audit_summary(org_id: str) -> dict:
        ...

    # Manual cache operations
    await cache.get("scan:abc123")
    await cache.set("scan:abc123", result, ttl=600)
    await cache.invalidate("scan:abc123")
    await cache.invalidate_pattern("audit:*")
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
from typing import Any, Callable, TypeVar

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None  # type: ignore[assignment]

from engine.core.config import get_settings

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


class QueryCache:
    """Async Redis cache with JSON serialisation and pattern invalidation."""

    def __init__(self, url: str | None = None, prefix: str = "zc") -> None:
        settings = get_settings()
        self._url = url or settings.redis_url
        self._prefix = prefix
        self._client: Any | None = None
        self._enabled = aioredis is not None

    async def _get_client(self) -> Any:
        if not self._enabled:
            return None
        if self._client is None:
            try:
                self._client = aioredis.from_url(
                    self._url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                )
                await self._client.ping()
            except Exception as exc:
                logger.warning("Redis cache unavailable: %s — running without cache", exc)
                self._enabled = False
                self._client = None
        return self._client

    def _key(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    # ── Core operations ──────────────────────────────────────────────────────

    async def get(self, key: str) -> Any | None:
        """Retrieve cached value, returning None on miss."""
        client = await self._get_client()
        if not client:
            return None
        try:
            raw = await client.get(self._key(key))
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:
            logger.debug("Cache GET error for %s: %s", key, exc)
            return None

    async def set(self, key: str, value: Any, ttl: int = 300) -> None:
        """Store a value in cache with TTL (seconds)."""
        client = await self._get_client()
        if not client:
            return
        try:
            raw = json.dumps(value, default=str)
            await client.set(self._key(key), raw, ex=ttl)
        except Exception as exc:
            logger.debug("Cache SET error for %s: %s", key, exc)

    async def invalidate(self, key: str) -> None:
        """Delete a specific cache key."""
        client = await self._get_client()
        if not client:
            return
        try:
            await client.delete(self._key(key))
        except Exception as exc:
            logger.debug("Cache DELETE error for %s: %s", key, exc)

    async def invalidate_pattern(self, pattern: str) -> int:
        """Delete all keys matching a glob pattern. Returns count deleted."""
        client = await self._get_client()
        if not client:
            return 0
        try:
            full = self._key(pattern)
            count = 0
            async for key in client.scan_iter(match=full, count=100):
                await client.delete(key)
                count += 1
            return count
        except Exception as exc:
            logger.debug("Cache INVALIDATE pattern error for %s: %s", pattern, exc)
            return 0

    async def flush(self) -> None:
        """Flush all cache keys under our prefix."""
        await self.invalidate_pattern("*")

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._client:
            await self._client.close()
            self._client = None

    # ── Stats ────────────────────────────────────────────────────────────────

    async def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        client = await self._get_client()
        if not client:
            return {"enabled": False}
        try:
            info = await client.info("stats")
            return {
                "enabled": True,
                "hits": info.get("keyspace_hits", 0),
                "misses": info.get("keyspace_misses", 0),
                "connected_clients": (await client.info("clients")).get("connected_clients", 0),
            }
        except Exception:
            return {"enabled": True, "error": "stats unavailable"}


# ── Singleton ────────────────────────────────────────────────────────────────

_cache_instance: QueryCache | None = None


def get_cache() -> QueryCache:
    """Get the global QueryCache singleton."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = QueryCache()
    return _cache_instance


# ── Decorator ────────────────────────────────────────────────────────────────


def _make_cache_key(prefix: str, args: tuple, kwargs: dict) -> str:
    """Build deterministic cache key from function arguments."""
    parts = [str(a) for a in args]
    parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
    raw = ":".join(parts)
    hashed = hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:12]
    return f"{prefix}:{hashed}"


def cached(ttl: int = 300, prefix: str = "") -> Callable:
    """Decorator to cache async function results in Redis.

    Args:
        ttl: Cache expiry in seconds (default 5 min).
        prefix: Cache key prefix (defaults to function name).
    """

    def decorator(fn: F) -> F:
        cache_prefix = prefix or fn.__qualname__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            cache = get_cache()
            key = _make_cache_key(cache_prefix, args, kwargs)

            # Try cache first
            hit = await cache.get(key)
            if hit is not None:
                return hit

            # Cache miss — execute function
            result = await fn(*args, **kwargs)

            # Store result
            await cache.set(key, result, ttl=ttl)
            return result

        # Attach helper to bypass cache
        wrapper.invalidate = lambda *a, **kw: get_cache().invalidate(  # type: ignore[attr-defined]
            _make_cache_key(cache_prefix, a, kw)
        )
        return wrapper  # type: ignore[return-value]

    return decorator

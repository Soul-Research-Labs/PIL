"""Rate limiting middleware using Redis sliding window.

Provides per-endpoint tier-based rate limiting:
  - Tier 1 (expensive): 2 req/min — fuzz campaigns, deep scans
  - Tier 2 (standard):  30 req/min — scans, reports, analysis
  - Tier 3 (light):     120 req/min — reads, listings, health
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Endpoint tier classification
TIER_1_PATTERNS = {
    "/api/v1/soul/fuzz",
    "/api/v1/soul/concolic",
    "/api/v1/soul/differential",
    "/api/v1/soul/property-test",
    "/api/v1/quickscan/deep",
}
TIER_2_PATTERNS = {
    "/api/v1/scans",
    "/api/v1/reports",
    "/api/v1/soul/quick-fuzz",
    "/api/v1/soul/targeted-fuzz",
    "/api/v1/soul/symbolic",
    "/api/v1/soul/bytecode-analysis",
    "/api/v1/soul/taint-analysis",
    "/api/v1/soul/gas-profile",
    "/api/v1/soul/scan",
    "/api/v1/quickscan/address",
    "/api/v1/quickscan/source",
}

TIER_LIMITS = {
    1: (2, 60),      # 2 requests per 60 seconds
    2: (30, 60),     # 30 requests per 60 seconds
    3: (120, 60),    # 120 requests per 60 seconds
}


def _get_tier(path: str) -> int:
    """Determine rate limit tier for a given path."""
    for pattern in TIER_1_PATTERNS:
        if path.startswith(pattern):
            return 1
    for pattern in TIER_2_PATTERNS:
        if path.startswith(pattern):
            return 2
    return 3


def _get_client_key(request: Request) -> str:
    """Get a unique key for the requesting client."""
    # Use auth token if present, else IP
    auth = request.headers.get("authorization", "")
    api_key = request.headers.get("x-api-key", "")
    if auth:
        identity = auth
    elif api_key:
        identity = api_key
    else:
        identity = request.client.host if request.client else "unknown"
    return hashlib.sha256(identity.encode()).hexdigest()[:16]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Redis-based sliding window rate limiter.

    Falls back to in-memory dict if Redis is unavailable.
    """

    def __init__(self, app: ASGIApp, redis_url: str | None = None) -> None:
        super().__init__(app)
        self._redis = None
        self._redis_url = redis_url
        # In-memory fallback: {key: [(timestamp, ...)]}
        self._memory_store: dict[str, list[float]] = {}

    async def _get_redis(self):
        """Lazy-init Redis connection."""
        if self._redis is None and self._redis_url:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(self._redis_url, decode_responses=True)
                await self._redis.ping()
            except Exception:
                logger.warning("Rate limiter: Redis unavailable, using in-memory fallback")
                self._redis = None
        return self._redis

    async def _check_rate_limit_redis(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """Check rate limit using Redis sorted set sliding window."""
        r = await self._get_redis()
        if not r:
            return self._check_rate_limit_memory(key, limit, window)

        now = time.time()
        pipe = r.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, window)
        results = await pipe.execute()
        count = results[2]
        remaining = max(0, limit - count)
        return count > limit, remaining

    def _check_rate_limit_memory(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """In-memory fallback rate limit check."""
        now = time.time()
        if key not in self._memory_store:
            self._memory_store[key] = []
        # Evict old entries
        self._memory_store[key] = [t for t in self._memory_store[key] if t > now - window]
        self._memory_store[key].append(now)
        count = len(self._memory_store[key])
        remaining = max(0, limit - count)
        return count > limit, remaining

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for health and docs
        path = request.url.path
        if path in ("/api/health", "/api/docs", "/api/openapi.json"):
            return await call_next(request)

        # Rate limit write operations strictly, GET requests at higher threshold
        if request.method in ("GET", "HEAD", "OPTIONS"):
            # Apply a relaxed rate limit to reads (prevent enumeration)
            identifier = self._get_identifier(request)
            key = f"rl:read:{identifier}"
            exceeded, remaining = await self._check_rate_limit(key, 300, 60)  # 300/min
            if exceeded:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": "60", "X-RateLimit-Remaining": str(remaining)},
                )
            response = await call_next(request)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            return response

        tier = _get_tier(path)
        limit, window = TIER_LIMITS[tier]
        client_key = _get_client_key(request)
        rate_key = f"rl:{client_key}:{tier}"

        exceeded, remaining = await self._check_rate_limit_redis(rate_key, limit, window)

        if exceeded:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": window,
                    "tier": tier,
                },
                headers={
                    "Retry-After": str(window),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

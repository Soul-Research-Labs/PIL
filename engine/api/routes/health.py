"""Health check endpoint — verifies all service dependencies."""

from __future__ import annotations

import logging
import shutil
import time

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.config import get_settings
from engine.core.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Quick liveness probe."""
    return {"status": "healthy", "service": "zaseon-engine"}


@router.get("/health/ready")
async def readiness_check(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Deep readiness check — verifies database, Redis, and Forge availability."""
    settings = get_settings()
    checks: dict[str, dict] = {}
    overall = True
    start = time.perf_counter()

    # ── PostgreSQL ───────────────────────────────────────────────────
    try:
        result = await db.execute(text("SELECT 1"))
        result.scalar()
        checks["postgres"] = {"status": "up"}
    except Exception as e:
        checks["postgres"] = {"status": "down", "error": str(e)}
        overall = False

    # ── Redis ────────────────────────────────────────────────────────
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        pong = await r.ping()
        checks["redis"] = {"status": "up" if pong else "down"}
        await r.aclose()
        if not pong:
            overall = False
    except Exception as e:
        checks["redis"] = {"status": "down", "error": str(e)}
        overall = False

    # ── Foundry (forge) ──────────────────────────────────────────────
    forge_path = shutil.which("forge") or shutil.which(
        "forge", path=settings.foundry_bin_path
    )
    if forge_path:
        checks["forge"] = {"status": "up", "path": forge_path}
    else:
        checks["forge"] = {"status": "unavailable", "note": "Foundry not installed"}
        # Forge is optional — don't fail overall health

    # ── MinIO / S3 ───────────────────────────────────────────────────
    try:
        import boto3
        from botocore.config import Config as BotoConfig

        s3 = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            config=BotoConfig(connect_timeout=3, read_timeout=3),
        )
        s3.head_bucket(Bucket=settings.s3_bucket_reports)
        checks["minio"] = {"status": "up"}
    except Exception as e:
        checks["minio"] = {"status": "down", "error": str(e)}
        # MinIO is soft-optional for health

    elapsed = round((time.perf_counter() - start) * 1000, 1)

    return {
        "status": "healthy" if overall else "degraded",
        "service": "zaseon-engine",
        "checks": checks,
        "latency_ms": elapsed,
    }


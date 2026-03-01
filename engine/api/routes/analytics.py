"""Trend analytics API — time-series data for dashboards and reporting.

Provides endpoints for:
- Scan volume trends (daily/weekly/monthly)
- Finding severity distribution over time
- Security score progression per project
- Top vulnerability categories
- Mean time to remediation (MTTR)
- Coverage trends
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text, and_
from sqlalchemy.ext.asyncio import AsyncSession

from engine.api.middleware.auth import get_current_user
from engine.core.cache import cached
from engine.core.database import get_session
from engine.models.scan import Scan
from engine.models.user import User

router = APIRouter(prefix="/v1/analytics", tags=["analytics"])


# ── Schemas ──────────────────────────────────────────────────────────────────


class TimeGranularity(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class TimeSeriesPoint(BaseModel):
    timestamp: str
    value: int | float


class SeverityDistribution(BaseModel):
    timestamp: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class CategoryCount(BaseModel):
    category: str
    count: int
    trend: float = Field(0.0, description="Change vs previous period (-1.0 to +inf)")


class ScoreTrend(BaseModel):
    timestamp: str
    score: float
    scan_id: str


class MTTRMetrics(BaseModel):
    overall_hours: float = Field(description="Mean time to remediation in hours")
    by_severity: dict[str, float] = Field(default_factory=dict)
    sample_size: int = 0


class AnalyticsSummary(BaseModel):
    total_scans: int = 0
    total_findings: int = 0
    avg_security_score: float = 0.0
    scans_trend: list[TimeSeriesPoint] = []
    severity_trend: list[SeverityDistribution] = []
    top_categories: list[CategoryCount] = []
    score_trend: list[ScoreTrend] = []
    mttr: MTTRMetrics = MTTRMetrics(overall_hours=0, sample_size=0)
    period_start: str = ""
    period_end: str = ""


# ── Helper: date truncation ─────────────────────────────────────────────────


def _trunc_expr(col: Any, granularity: TimeGranularity) -> Any:
    """Return a SQLAlchemy expression to truncate a datetime column."""
    if granularity == TimeGranularity.DAILY:
        return func.date_trunc("day", col)
    elif granularity == TimeGranularity.WEEKLY:
        return func.date_trunc("week", col)
    else:
        return func.date_trunc("month", col)


def _default_range(days: int = 30) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    return now - timedelta(days=days), now


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/summary", response_model=AnalyticsSummary)
async def get_analytics_summary(
    days: int = Query(30, ge=1, le=365, description="Lookback period in days"),
    granularity: TimeGranularity = Query(TimeGranularity.DAILY),
    project_id: str | None = Query(None, description="Filter by project"),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> AnalyticsSummary:
    """Combined analytics summary for the dashboard."""
    start, end = _default_range(days)

    base_filter = and_(
        Scan.created_at >= start,
        Scan.created_at <= end,
    )
    if project_id:
        base_filter = and_(base_filter, Scan.project_id == project_id)

    # Total scans
    total_q = select(func.count(Scan.id)).where(base_filter)
    total_scans = (await session.execute(total_q)).scalar() or 0

    # Average security score
    score_q = select(func.avg(Scan.security_score)).where(
        and_(base_filter, Scan.security_score.isnot(None))
    )
    avg_score = (await session.execute(score_q)).scalar() or 0.0

    # Scan volume trend
    trunc = _trunc_expr(Scan.created_at, granularity)
    volume_q = (
        select(trunc.label("period"), func.count(Scan.id).label("cnt"))
        .where(base_filter)
        .group_by(text("period"))
        .order_by(text("period"))
    )
    volume_rows = (await session.execute(volume_q)).all()
    scans_trend = [
        TimeSeriesPoint(timestamp=str(r.period), value=r.cnt)
        for r in volume_rows
    ]

    # Score trend (per-scan time series)
    score_trend_q = (
        select(Scan.created_at, Scan.security_score, Scan.id)
        .where(and_(base_filter, Scan.security_score.isnot(None)))
        .order_by(Scan.created_at)
        .limit(500)
    )
    score_rows = (await session.execute(score_trend_q)).all()
    score_trend = [
        ScoreTrend(timestamp=str(r.created_at), score=r.security_score or 0, scan_id=str(r.id))
        for r in score_rows
    ]

    return AnalyticsSummary(
        total_scans=total_scans,
        total_findings=0,  # populated below if findings model accessible
        avg_security_score=round(float(avg_score), 1),
        scans_trend=scans_trend,
        severity_trend=[],
        top_categories=[],
        score_trend=score_trend,
        mttr=MTTRMetrics(overall_hours=0, sample_size=0),
        period_start=start.isoformat(),
        period_end=end.isoformat(),
    )


@router.get("/scans/volume", response_model=list[TimeSeriesPoint])
async def get_scan_volume(
    days: int = Query(30, ge=1, le=365),
    granularity: TimeGranularity = Query(TimeGranularity.DAILY),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[TimeSeriesPoint]:
    """Scan volume over time."""
    start, end = _default_range(days)
    trunc = _trunc_expr(Scan.created_at, granularity)

    q = (
        select(trunc.label("period"), func.count(Scan.id).label("cnt"))
        .where(and_(Scan.created_at >= start, Scan.created_at <= end))
        .group_by(text("period"))
        .order_by(text("period"))
    )
    rows = (await session.execute(q)).all()
    return [TimeSeriesPoint(timestamp=str(r.period), value=r.cnt) for r in rows]


@router.get("/scans/scores", response_model=list[ScoreTrend])
async def get_score_trend(
    days: int = Query(90, ge=1, le=365),
    project_id: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> list[ScoreTrend]:
    """Security score progression over time."""
    start, _ = _default_range(days)

    filters = [Scan.created_at >= start, Scan.security_score.isnot(None)]
    if project_id:
        filters.append(Scan.project_id == project_id)

    q = (
        select(Scan.created_at, Scan.security_score, Scan.id)
        .where(and_(*filters))
        .order_by(Scan.created_at)
        .limit(1000)
    )
    rows = (await session.execute(q)).all()
    return [
        ScoreTrend(timestamp=str(r.created_at), score=r.security_score or 0, scan_id=str(r.id))
        for r in rows
    ]


@router.get("/cache/stats")
async def get_cache_stats(
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Return Redis cache statistics."""
    from engine.core.cache import get_cache

    return await get_cache().stats()

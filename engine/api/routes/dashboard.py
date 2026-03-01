"""Dashboard stats endpoint."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select, case, and_
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.database import get_db
from engine.api.middleware.auth import get_current_user
from engine.models.scan import Finding, Project, Scan
from engine.models.user import User

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class SeverityDistribution(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0
    GAS: int = 0


class RecentScanResponse(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    scan_type: str
    status: str
    security_score: float | None
    findings_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class DashboardStatsResponse(BaseModel):
    total_projects: int
    total_scans: int
    total_findings: int
    critical_findings: int
    avg_security_score: float
    scans_this_month: int
    recent_scans: list[RecentScanResponse]
    severity_distribution: SeverityDistribution


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DashboardStatsResponse:
    """Aggregate dashboard statistics across projects, scans, and findings."""

    # Count projects
    total_projects = (await db.execute(select(func.count(Project.id)))).scalar_one() or 0

    # Count scans
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar_one() or 0

    # Count findings
    total_findings = (await db.execute(select(func.count(Finding.id)))).scalar_one() or 0

    # Critical findings count
    critical_findings = (
        await db.execute(
            select(func.count(Finding.id)).where(Finding.severity == "CRITICAL")
        )
    ).scalar_one() or 0

    # Average security score (completed scans only)
    avg_score_result = (
        await db.execute(
            select(func.avg(Scan.security_score)).where(
                Scan.security_score.isnot(None),
                Scan.status == "COMPLETED",
            )
        )
    ).scalar_one()
    avg_security_score = round(float(avg_score_result), 1) if avg_score_result else 0.0

    # Scans this month
    month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    scans_this_month = (
        await db.execute(
            select(func.count(Scan.id)).where(Scan.created_at >= month_start)
        )
    ).scalar_one() or 0

    # Recent 10 scans
    recent_result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(10)
    )
    recent_scans = [
        RecentScanResponse(
            id=s.id,
            project_id=s.project_id,
            scan_type=s.scan_type,
            status=s.status,
            security_score=s.security_score,
            findings_count=s.findings_count,
            created_at=s.created_at,
        )
        for s in recent_result.scalars().all()
    ]

    # Severity distribution
    sev_result = await db.execute(
        select(
            Finding.severity,
            func.count(Finding.id),
        ).group_by(Finding.severity)
    )
    sev_map = {row[0]: row[1] for row in sev_result.all()}
    severity_distribution = SeverityDistribution(
        CRITICAL=sev_map.get("CRITICAL", 0),
        HIGH=sev_map.get("HIGH", 0),
        MEDIUM=sev_map.get("MEDIUM", 0),
        LOW=sev_map.get("LOW", 0),
        INFO=sev_map.get("INFO", 0),
        GAS=sev_map.get("GAS", 0),
    )

    return DashboardStatsResponse(
        total_projects=total_projects,
        total_scans=total_scans,
        total_findings=total_findings,
        critical_findings=critical_findings,
        avg_security_score=avg_security_score,
        scans_this_month=scans_this_month,
        recent_scans=recent_scans,
        severity_distribution=severity_distribution,
    )

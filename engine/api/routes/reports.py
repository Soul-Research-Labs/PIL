"""Report endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.database import get_db
from engine.models.scan import Report
from engine.models.user import User
from engine.api.middleware.auth import get_current_user

router = APIRouter()


class ReportResponse(BaseModel):
    """Schema for report response."""

    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    report_type: str
    format: str
    file_size_bytes: int
    is_published: bool
    public_url: str | None
    public_slug: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportGenerate(BaseModel):
    """Schema for generating a report."""

    scan_id: uuid.UUID
    title: str = "Security Audit Report"
    report_type: str = "full"


@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    scan_id: uuid.UUID | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Report]:
    """List reports."""
    query = select(Report).order_by(Report.created_at.desc()).limit(50)
    if scan_id:
        query = query.where(Report.scan_id == scan_id)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/generate", response_model=ReportResponse, status_code=201)
async def generate_report(
    payload: ReportGenerate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Report:
    """Generate a new audit report for a scan."""
    # Create report record
    report = Report(
        scan_id=payload.scan_id,
        title=payload.title,
        report_type=payload.report_type,
        file_key=f"reports/{payload.scan_id}/{uuid.uuid4()}.pdf",
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    # Dispatch to Celery for actual generation
    from engine.pipeline.tasks import generate_report as gen_report_task

    gen_report_task.delay(str(payload.scan_id), "pdf")

    return report


@router.post("/{report_id}/publish")
async def publish_report(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Publish a report with a public URL."""
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report.is_published = True
    report.public_slug = str(uuid.uuid4())[:12]
    report.public_url = f"/reports/public/{report.public_slug}"
    await db.flush()
    return {"public_url": report.public_url}

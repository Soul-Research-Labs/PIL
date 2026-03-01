"""Scan management endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from engine.core.database import get_db
from engine.core.types import ScanStatus, ScanType
from engine.models.scan import Scan
from engine.models.user import User
from engine.api.middleware.auth import get_current_user

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class ScanCreate(BaseModel):
    """Schema for triggering a new smart contract scan."""

    project_id: uuid.UUID
    scan_type: ScanType = ScanType.SMART_CONTRACT
    branch: str | None = None
    commit_sha: str | None = None


class ScanResponse(BaseModel):
    """Schema for scan response."""

    id: uuid.UUID
    project_id: uuid.UUID
    scan_type: str
    status: str
    trigger: str
    commit_sha: str | None
    branch: str | None
    security_score: float | None
    threat_score: float | None
    total_lines_scanned: int
    findings_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/", response_model=list[ScanResponse])
async def list_scans(
    project_id: uuid.UUID | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Scan]:
    """List scans, optionally filtered by project."""
    query = select(Scan).order_by(Scan.created_at.desc()).limit(50)
    if project_id:
        query = query.where(Scan.project_id == project_id)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    payload: ScanCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan:
    """Trigger a new scan for a project."""
    scan = Scan(
        project_id=payload.project_id,
        scan_type=payload.scan_type.value,
        status=ScanStatus.PENDING.value,
        trigger="manual",
        branch=payload.branch,
        commit_sha=payload.commit_sha,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Dispatch to Celery task queue
    from engine.pipeline.tasks import run_scan as run_scan_task

    run_scan_task.delay(str(scan.id), str(payload.project_id), {})

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Scan:
    """Get a scan by ID."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

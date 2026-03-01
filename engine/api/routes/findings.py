"""Finding endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.database import get_db
from engine.models.scan import Finding
from engine.models.user import User
from engine.api.middleware.auth import get_current_user

router = APIRouter()


class FindingResponse(BaseModel):
    """Schema for finding response."""

    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    description: str
    severity: str
    status: str
    category: str
    cwe_id: str
    scwe_id: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    cvss_vector: str
    cvss_score: float
    poc_script: str | None
    poc_output: str | None
    remediation: str
    patch_diff: str | None
    gas_saved: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    """Schema for updating a finding."""

    status: str | None = None


@router.get("/", response_model=list[FindingResponse])
async def list_findings(
    scan_id: uuid.UUID | None = None,
    severity: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Finding]:
    """List findings with optional filters."""
    query = select(Finding).limit(100)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Finding:
    """Get a finding by ID."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Finding:
    """Update a finding (e.g. change status)."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if payload.status is not None:
        finding.status = payload.status
    await db.flush()
    await db.refresh(finding)
    return finding


class BulkFindingUpdate(BaseModel):
    """Schema for updating multiple findings at once."""

    finding_ids: list[uuid.UUID]
    status: str


class BulkUpdateResponse(BaseModel):
    """Response for bulk update."""

    updated: int
    ids: list[str]


@router.patch("/bulk/status", response_model=BulkUpdateResponse)
async def bulk_update_findings(
    payload: BulkFindingUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Bulk-update the status of multiple findings."""
    if len(payload.finding_ids) > 500:
        raise HTTPException(status_code=400, detail="Maximum 500 findings per batch")

    updated_ids: list[str] = []
    for fid in payload.finding_ids:
        finding = await db.get(Finding, fid)
        if finding:
            finding.status = payload.status
            updated_ids.append(str(fid))
    await db.flush()
    return {"updated": len(updated_ids), "ids": updated_ids}


@router.delete("/{finding_id}", status_code=204)
async def delete_finding(
    finding_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete (dismiss) a finding."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    await db.delete(finding)
    await db.flush()

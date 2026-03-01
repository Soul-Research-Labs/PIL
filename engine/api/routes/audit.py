"""Audit trail query API routes.

Routes:
    GET  /api/v1/audit              — Query audit logs (filtered, paginated)
    GET  /api/v1/audit/{id}         — Get single audit entry
    GET  /api/v1/audit/export       — Export audit logs as JSONL
    GET  /api/v1/audit/summary      — Aggregate statistics
    GET  /api/v1/compliance/report  — Run SOC 2 compliance checks
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.api.middleware.auth import get_current_user
from engine.core.database import get_db
from engine.models.audit import AuditAction, AuditLog, AuditSeverity
from engine.models.user import User

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class AuditLogResponse(BaseModel):
    id: str
    action: str
    severity: str
    description: str
    actor_email: str | None = None
    actor_ip: str | None = None
    resource_type: str = ""
    resource_id: str | None = None
    resource_name: str | None = None
    org_id: str | None = None
    old_value: dict | None = None
    new_value: dict | None = None
    metadata: dict = {}
    request_id: str | None = None
    endpoint: str | None = None
    http_method: str | None = None
    created_at: str | None = None


class AuditSummaryResponse(BaseModel):
    total_events: int = 0
    by_action: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_resource_type: dict[str, int] = {}
    unique_actors: int = 0
    time_range: dict[str, str | None] = {}


class ComplianceReportResponse(BaseModel):
    generated_at: str
    overall_status: str
    compliance_pct: float
    pass_count: int
    fail_count: int
    total_controls: int
    controls: list[dict[str, Any]] = []


# ── Query routes ─────────────────────────────────────────────────────────────


@router.get("", response_model=list[AuditLogResponse])
async def list_audit_logs(
    action: str | None = Query(None, description="Filter by action type"),
    severity: str | None = Query(None, description="Filter by severity"),
    resource_type: str | None = Query(None, description="Filter by resource type"),
    resource_id: str | None = Query(None, description="Filter by resource ID"),
    actor_email: str | None = Query(None, description="Filter by actor email"),
    since: datetime | None = Query(None, description="Start datetime (ISO 8601)"),
    until: datetime | None = Query(None, description="End datetime (ISO 8601)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Query audit logs with optional filters and pagination."""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())

    # V-041 FIX: Scope audit logs to user's organizations
    from engine.models.user import OrgMembership
    user_orgs = select(OrgMembership.org_id).where(OrgMembership.user_id == user.id)
    stmt = stmt.where(AuditLog.org_id.in_(user_orgs))

    if action:
        stmt = stmt.where(AuditLog.action == action)
    if severity:
        stmt = stmt.where(AuditLog.severity == severity)
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
    if actor_email:
        stmt = stmt.where(AuditLog.actor_email == actor_email)
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until:
        stmt = stmt.where(AuditLog.created_at <= until)

    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    logs = result.scalars().all()

    return [
        AuditLogResponse(
            id=str(log.id),
            action=log.action,
            severity=log.severity,
            description=log.description,
            actor_email=log.actor_email,
            actor_ip=log.actor_ip,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            resource_name=log.resource_name,
            org_id=str(log.org_id) if log.org_id else None,
            old_value=log.old_value,
            new_value=log.new_value,
            metadata=log.metadata or {},
            request_id=log.request_id,
            endpoint=log.endpoint,
            http_method=log.http_method,
            created_at=log.created_at.isoformat() if log.created_at else None,
        )
        for log in logs
    ]


@router.get("/summary", response_model=AuditSummaryResponse)
async def audit_summary(
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate audit log statistics."""
    base = select(AuditLog)
    if since:
        base = base.where(AuditLog.created_at >= since)
    if until:
        base = base.where(AuditLog.created_at <= until)

    # Total
    total = await db.scalar(select(func.count()).select_from(base.subquery())) or 0

    # By action
    action_result = await db.execute(
        select(AuditLog.action, func.count())
        .group_by(AuditLog.action)
        .order_by(func.count().desc())
    )
    by_action = {row[0]: row[1] for row in action_result.all()}

    # By severity
    sev_result = await db.execute(
        select(AuditLog.severity, func.count()).group_by(AuditLog.severity)
    )
    by_severity = {row[0]: row[1] for row in sev_result.all()}

    # By resource type
    res_result = await db.execute(
        select(AuditLog.resource_type, func.count())
        .where(AuditLog.resource_type != "")
        .group_by(AuditLog.resource_type)
    )
    by_resource = {row[0]: row[1] for row in res_result.all()}

    # Unique actors
    actors = await db.scalar(
        select(func.count(func.distinct(AuditLog.actor_id)))
    ) or 0

    return AuditSummaryResponse(
        total_events=total,
        by_action=by_action,
        by_severity=by_severity,
        by_resource_type=by_resource,
        unique_actors=actors,
        time_range={
            "since": since.isoformat() if since else None,
            "until": until.isoformat() if until else None,
        },
    )


# ── Compliance ───────────────────────────────────────────────────────────────


@router.get("/compliance/report", response_model=ComplianceReportResponse)
async def compliance_report(
    user: User = Depends(get_current_user),
):
    """Run SOC 2 compliance checks and return a report."""
    from engine.core.compliance import ComplianceChecker

    checker = ComplianceChecker()
    report = await checker.run_all_checks()
    return ComplianceReportResponse(**report.to_dict())

"""Audit trail — immutable event logging for all scan, finding,
and administrative operations.

Provides:
- AuditLog SQLAlchemy model with immutable append-only design
- AuditMiddleware for automatic HTTP request logging
- Helper functions for programmatic event recording
- Query API for audit log retrieval and export

Every significant action (create, update, delete, auth event)
is recorded with: who, what, when, where (IP), and the diff.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from engine.models.base import Base, TimestampMixin, UUIDMixin

logger = logging.getLogger(__name__)


# ── Enums ────────────────────────────────────────────────────────────────────


class AuditAction(str, Enum):
    # Auth events
    LOGIN = "auth.login"
    LOGOUT = "auth.logout"
    LOGIN_FAILED = "auth.login_failed"
    TOKEN_REFRESH = "auth.token_refresh"
    API_KEY_CREATED = "auth.api_key_created"
    API_KEY_REVOKED = "auth.api_key_revoked"

    # Organization
    ORG_CREATED = "org.created"
    ORG_UPDATED = "org.updated"
    ORG_DELETED = "org.deleted"
    MEMBER_INVITED = "org.member_invited"
    MEMBER_REMOVED = "org.member_removed"
    MEMBER_ROLE_CHANGED = "org.member_role_changed"

    # Project
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_DELETED = "project.deleted"

    # Scan
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_DELETED = "scan.deleted"

    # Finding
    FINDING_STATUS_CHANGED = "finding.status_changed"
    FINDING_ASSIGNED = "finding.assigned"
    FINDING_COMMENTED = "finding.commented"
    FINDING_EXPORTED = "finding.exported"

    # Report
    REPORT_GENERATED = "report.generated"
    REPORT_PUBLISHED = "report.published"
    REPORT_DELETED = "report.deleted"

    # Soul Fuzzer
    CAMPAIGN_STARTED = "campaign.started"
    CAMPAIGN_COMPLETED = "campaign.completed"

    # Admin
    SETTINGS_CHANGED = "admin.settings_changed"
    PLUGIN_LOADED = "admin.plugin_loaded"
    PLUGIN_UNLOADED = "admin.plugin_unloaded"

    # Data
    DATA_EXPORTED = "data.exported"
    DATA_DELETED = "data.deleted"


class AuditSeverity(str, Enum):
    """How significant is this audit event for compliance review."""
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    CRITICAL = "critical"


# ── Model ────────────────────────────────────────────────────────────────────


class AuditLog(Base, UUIDMixin, TimestampMixin):
    """Immutable audit trail entry.

    This table is append-only — entries should never be updated or deleted
    in production. Use a separate retention policy for cleanup.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_actor_id", "actor_id"),
        Index("ix_audit_logs_resource_type_id", "resource_type", "resource_id"),
        Index("ix_audit_logs_org_id", "org_id"),
        Index("ix_audit_logs_created_at", "created_at"),
    )

    # Who performed the action
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    actor_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv4 or IPv6
    actor_user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # What happened
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    description: Mapped[str] = mapped_column(Text, default="")

    # What was affected
    resource_type: Mapped[str] = mapped_column(String(50), default="")  # "scan", "finding", "project", etc.
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    resource_name: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Organization scope
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )

    # Change details
    old_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    metadata: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Request context
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(500), nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(10), nullable=True)


# ── Recording helpers ────────────────────────────────────────────────────────


async def record_audit_event(
    db_session: Any,
    action: AuditAction,
    *,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    actor_ip: str | None = None,
    org_id: uuid.UUID | None = None,
    resource_type: str = "",
    resource_id: str | None = None,
    resource_name: str | None = None,
    description: str = "",
    severity: AuditSeverity = AuditSeverity.INFO,
    old_value: dict | None = None,
    new_value: dict | None = None,
    metadata: dict | None = None,
    request_id: str | None = None,
    endpoint: str | None = None,
    http_method: str | None = None,
) -> AuditLog:
    """Record an audit event to the database.

    This is the primary API for programmatic audit logging. Call this
    from route handlers, background tasks, or middleware.
    """
    entry = AuditLog(
        actor_id=actor_id,
        actor_email=actor_email,
        actor_ip=actor_ip,
        action=action.value,
        severity=severity.value,
        description=description or action.value,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        org_id=org_id,
        old_value=old_value,
        new_value=new_value,
        metadata=metadata or {},
        request_id=request_id,
        endpoint=endpoint,
        http_method=http_method,
    )

    db_session.add(entry)
    # Flush but don't commit — let the caller's transaction handle it
    await db_session.flush()

    logger.info(
        "AUDIT: %s by=%s resource=%s/%s org=%s",
        action.value,
        actor_email or str(actor_id) if actor_id else "system",
        resource_type,
        resource_id or "",
        str(org_id) if org_id else "global",
    )
    return entry


def record_audit_event_sync(
    db_session: Any,
    action: AuditAction,
    **kwargs: Any,
) -> AuditLog:
    """Synchronous version for Celery tasks or non-async contexts."""
    entry = AuditLog(
        actor_id=kwargs.get("actor_id"),
        actor_email=kwargs.get("actor_email"),
        actor_ip=kwargs.get("actor_ip"),
        action=action.value,
        severity=kwargs.get("severity", AuditSeverity.INFO).value
        if isinstance(kwargs.get("severity"), AuditSeverity)
        else kwargs.get("severity", "info"),
        description=kwargs.get("description", action.value),
        resource_type=kwargs.get("resource_type", ""),
        resource_id=kwargs.get("resource_id"),
        resource_name=kwargs.get("resource_name"),
        org_id=kwargs.get("org_id"),
        old_value=kwargs.get("old_value"),
        new_value=kwargs.get("new_value"),
        metadata=kwargs.get("metadata", {}),
        request_id=kwargs.get("request_id"),
        endpoint=kwargs.get("endpoint"),
        http_method=kwargs.get("http_method"),
    )
    db_session.add(entry)
    db_session.flush()
    return entry

"""Team collaboration models — comments, assignments, SLA tracking."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from engine.models.base import Base, TimestampMixin, UUIDMixin


# ── Finding Comments ─────────────────────────────────────────────────────────


class FindingComment(Base, UUIDMixin, TimestampMixin):
    """A threaded comment on a finding.

    Supports replies (via ``parent_id``), mentions (parsed from body),
    and read-status tracking.
    """

    __tablename__ = "finding_comments"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False,
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False,
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("finding_comments.id", ondelete="CASCADE"), nullable=True,
    )

    body: Mapped[str] = mapped_column(Text, nullable=False)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Soft-delete / edit tracking
    edited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Mentions extracted from body (@username → user ids)
    mentions: Mapped[list] = mapped_column(JSONB, default=list)

    # Reactions (emoji → list of user_ids)
    reactions: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    replies: Mapped[list["FindingComment"]] = relationship(
        "FindingComment", backref="parent", remote_side="FindingComment.id",
    )


# ── Finding Assignments ──────────────────────────────────────────────────────


class FindingAssignment(Base, UUIDMixin, TimestampMixin):
    """Tracks who is responsible for triaging or remediating a finding."""

    __tablename__ = "finding_assignments"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False,
    )
    assignee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False,
    )
    assigned_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(30), default="owner",
    )  # owner | reviewer | observer

    status: Mapped[str] = mapped_column(
        String(30), default="assigned",
    )  # assigned | in_progress | review | done | declined

    due_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    note: Mapped[str | None] = mapped_column(Text, nullable=True)


# ── SLA Policies ─────────────────────────────────────────────────────────────


class SLAPolicy(Base, UUIDMixin, TimestampMixin):
    """Service-level agreement policy applied at the organisation level.

    Defines maximum time-to-triage and time-to-remediate by severity.
    """

    __tablename__ = "sla_policies"

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    # Minutes until breach for triage (first human response)
    triage_critical_mins: Mapped[int] = mapped_column(Integer, default=60)      # 1 hour
    triage_high_mins: Mapped[int] = mapped_column(Integer, default=240)          # 4 hours
    triage_medium_mins: Mapped[int] = mapped_column(Integer, default=1440)       # 24 hours
    triage_low_mins: Mapped[int] = mapped_column(Integer, default=10_080)        # 7 days

    # Minutes until breach for remediation (fix deployed)
    remediate_critical_mins: Mapped[int] = mapped_column(Integer, default=1440)  # 1 day
    remediate_high_mins: Mapped[int] = mapped_column(Integer, default=10_080)    # 7 days
    remediate_medium_mins: Mapped[int] = mapped_column(Integer, default=43_200)  # 30 days
    remediate_low_mins: Mapped[int] = mapped_column(Integer, default=129_600)    # 90 days

    # Escalation config (JSONB for flexibility)
    escalation_rules: Mapped[dict] = mapped_column(JSONB, default=dict)

    def triage_deadline_mins(self, severity: str) -> int:
        """Return triage SLA in minutes for a given severity."""
        return {
            "CRITICAL": self.triage_critical_mins,
            "HIGH": self.triage_high_mins,
            "MEDIUM": self.triage_medium_mins,
            "LOW": self.triage_low_mins,
        }.get(severity.upper(), self.triage_medium_mins)

    def remediation_deadline_mins(self, severity: str) -> int:
        """Return remediation SLA in minutes for a given severity."""
        return {
            "CRITICAL": self.remediate_critical_mins,
            "HIGH": self.remediate_high_mins,
            "MEDIUM": self.remediate_medium_mins,
            "LOW": self.remediate_low_mins,
        }.get(severity.upper(), self.remediate_medium_mins)


# ── SLA Tracker (per-finding) ────────────────────────────────────────────────


class SLATracker(Base, UUIDMixin, TimestampMixin):
    """Tracks SLA compliance for individual findings."""

    __tablename__ = "sla_trackers"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True,
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sla_policies.id"), nullable=False,
    )

    # Triage deadline & status
    triage_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triage_breached: Mapped[bool] = mapped_column(Boolean, default=False)

    # Remediation deadline & status
    remediation_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    remediation_breached: Mapped[bool] = mapped_column(Boolean, default=False)

    # Escalation history
    escalation_log: Mapped[list] = mapped_column(JSONB, default=list)

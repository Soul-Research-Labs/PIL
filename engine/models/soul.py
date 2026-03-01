"""Soul Protocol campaign and finding ORM models.

Maps to the tables created in migration 002_soul_campaigns.py.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
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


class SoulCampaign(Base, UUIDMixin, TimestampMixin):
    """A Soul Protocol fuzzing campaign execution."""

    __tablename__ = "soul_campaigns"

    # ── Core fields ──────────────────────────────────────────────────
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(30), default="pending")
    mode: Mapped[str] = mapped_column(String(30), default="standard")
    contract_name: Mapped[str] = mapped_column(String(300), default="SoulContract")

    # ── Source ───────────────────────────────────────────────────────
    source_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    bytecode: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Configuration ────────────────────────────────────────────────
    config: Mapped[dict] = mapped_column(JSONB, default=dict)

    # ── Timing ───────────────────────────────────────────────────────
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_sec: Mapped[float] = mapped_column(Float, default=0.0)

    # ── Results ──────────────────────────────────────────────────────
    total_iterations: Mapped[int] = mapped_column(Integer, default=0)
    violations_count: Mapped[int] = mapped_column(Integer, default=0)
    coverage: Mapped[dict] = mapped_column(JSONB, default=dict)
    mutation_stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    corpus_size: Mapped[int] = mapped_column(Integer, default=0)
    unique_paths: Mapped[int] = mapped_column(Integer, default=0)
    score: Mapped[float] = mapped_column(Float, default=100.0)

    # ── v2 Engine Results (JSONB) ────────────────────────────────────
    invariant_report: Mapped[dict] = mapped_column(JSONB, default=dict)
    bytecode_report: Mapped[dict] = mapped_column(JSONB, default=dict)
    gas_profile: Mapped[dict] = mapped_column(JSONB, default=dict)
    exploit_chains: Mapped[dict] = mapped_column(JSONB, default=list)
    taint_analysis: Mapped[dict] = mapped_column(JSONB, default=dict)
    state_snapshots: Mapped[dict] = mapped_column(JSONB, default=dict)

    # ── Full result blob ─────────────────────────────────────────────
    result: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Relationships ────────────────────────────────────────────────
    findings: Mapped[list["SoulFinding"]] = relationship(
        back_populates="campaign",
        order_by="SoulFinding.severity",
        cascade="all, delete-orphan",
    )


class SoulFinding(Base, UUIDMixin, TimestampMixin):
    """A finding from a Soul Protocol fuzzing campaign."""

    __tablename__ = "soul_findings"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("soul_campaigns.id", ondelete="CASCADE"), nullable=False
    )

    # ── Core ─────────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(100), default="")
    detector_id: Mapped[str] = mapped_column(String(50), default="")
    finding_type: Mapped[str] = mapped_column(String(30), default="violation")  # violation, static, invariant

    # ── Location ─────────────────────────────────────────────────────
    file_path: Mapped[str] = mapped_column(Text, default="")
    start_line: Mapped[int] = mapped_column(Integer, default=0)
    end_line: Mapped[int] = mapped_column(Integer, default=0)
    code_snippet: Mapped[str] = mapped_column(Text, default="")

    # ── Remediation ──────────────────────────────────────────────────
    remediation: Mapped[str] = mapped_column(Text, default="")
    poc_code: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Metadata ─────────────────────────────────────────────────────
    metadata: Mapped[dict] = mapped_column(JSONB, default=dict)

    # ── Relationships ────────────────────────────────────────────────
    campaign: Mapped["SoulCampaign"] = relationship(back_populates="findings")

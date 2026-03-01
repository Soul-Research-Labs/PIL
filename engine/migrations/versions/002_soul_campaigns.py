"""Add Soul fuzzer campaign tables

Revision ID: 002_soul_campaigns
Revises: 001_initial
Create Date: 2025-01-02 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


revision: str = "002_soul_campaigns"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Soul Fuzzer Campaigns ────────────────────────────────────────────
    op.create_table(
        "soul_campaigns",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("status", sa.String(20), default="pending"),
        sa.Column("mode", sa.String(20), default="standard"),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("contract_source", sa.Text, nullable=True),
        sa.Column("repo_url", sa.Text, nullable=True),
        sa.Column("contract_address", sa.String(42), nullable=True),
        sa.Column("chain", sa.String(30), nullable=True),
        # ── Soul v2 fields ───────────────────────────────────────────────
        sa.Column("config", JSONB, default={}),
        sa.Column("iterations_completed", sa.Integer, default=0),
        sa.Column("max_iterations", sa.Integer, default=50000),
        sa.Column("coverage_pct", sa.Float, default=0.0),
        sa.Column("branch_coverage_pct", sa.Float, default=0.0),
        sa.Column("findings_count", sa.Integer, default=0),
        sa.Column("security_score", sa.Float, nullable=True),
        sa.Column("phase", sa.String(50), default="initializing"),
        sa.Column("current_phase_number", sa.Integer, default=0),
        sa.Column("total_phases", sa.Integer, default=18),
        sa.Column("engine_stats", JSONB, default={}),
        # ── v2 Engine Reports ────────────────────────────────────────────
        sa.Column("invariant_report", JSONB, default={}),
        sa.Column("bytecode_report", JSONB, default={}),
        sa.Column("gas_profile", JSONB, default={}),
        sa.Column("exploit_chains", JSONB, default=[]),
        sa.Column("taint_analysis", JSONB, default={}),
        sa.Column("state_snapshots", JSONB, default=[]),
        # ── Timing ───────────────────────────────────────────────────────
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Soul Campaign Findings ───────────────────────────────────────────
    op.create_table(
        "soul_findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", UUID(as_uuid=True), sa.ForeignKey("soul_campaigns.id"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(100), default=""),
        sa.Column("detector", sa.String(100), default=""),
        sa.Column("confidence", sa.Float, default=0.0),
        sa.Column("file_path", sa.Text, default=""),
        sa.Column("start_line", sa.Integer, default=0),
        sa.Column("end_line", sa.Integer, default=0),
        sa.Column("code_snippet", sa.Text, default=""),
        sa.Column("trigger_input", JSONB, default={}),
        sa.Column("invariant_violated", sa.String(200), default=""),
        sa.Column("exploit_chain_id", sa.String(100), nullable=True),
        sa.Column("poc_script", sa.Text, nullable=True),
        sa.Column("remediation", sa.Text, default=""),
        sa.Column("metadata", JSONB, default={}),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Indexes ──────────────────────────────────────────────────────────
    op.create_index("ix_soul_campaigns_status", "soul_campaigns", ["status"])
    op.create_index("ix_soul_campaigns_project_id", "soul_campaigns", ["project_id"])
    op.create_index("ix_soul_findings_campaign_id", "soul_findings", ["campaign_id"])
    op.create_index("ix_soul_findings_severity", "soul_findings", ["severity"])


def downgrade() -> None:
    op.drop_table("soul_findings")
    op.drop_table("soul_campaigns")

"""Reconcile soul_campaigns and soul_findings tables with ORM models.

Migration 002 created the tables with a schema that drifted from the ORM
models in engine/models/soul.py.  This migration brings the DB into sync
with the current ORM so that all runtime operations (INSERT, SELECT, UPDATE)
work without error.

Revision ID: 004
Revises: 003
Create Date: 2026-02-28
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── soul_campaigns: add columns the ORM expects ──────────────────────
    op.add_column(
        "soul_campaigns",
        sa.Column("contract_name", sa.String(300), server_default="SoulContract"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("bytecode", sa.Text, nullable=True),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("violations_count", sa.Integer, server_default="0"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("coverage", JSONB, server_default="{}"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("mutation_stats", JSONB, server_default="{}"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("corpus_size", sa.Integer, server_default="0"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("unique_paths", sa.Integer, server_default="0"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("result", JSONB, server_default="{}"),
    )

    # ── soul_campaigns: rename columns that changed names ────────────────
    op.alter_column(
        "soul_campaigns", "contract_source", new_column_name="source_code"
    )
    op.alter_column(
        "soul_campaigns", "iterations_completed", new_column_name="total_iterations"
    )
    op.alter_column(
        "soul_campaigns", "security_score", new_column_name="score"
    )
    op.alter_column(
        "soul_campaigns", "duration_seconds", new_column_name="duration_sec"
    )

    # ── soul_campaigns: drop columns the ORM no longer uses ──────────────
    op.drop_column("soul_campaigns", "source_type")
    op.drop_column("soul_campaigns", "repo_url")
    op.drop_column("soul_campaigns", "contract_address")
    op.drop_column("soul_campaigns", "chain")
    op.drop_column("soul_campaigns", "max_iterations")
    op.drop_column("soul_campaigns", "coverage_pct")
    op.drop_column("soul_campaigns", "branch_coverage_pct")
    op.drop_column("soul_campaigns", "findings_count")
    op.drop_column("soul_campaigns", "phase")
    op.drop_column("soul_campaigns", "current_phase_number")
    op.drop_column("soul_campaigns", "total_phases")
    op.drop_column("soul_campaigns", "engine_stats")

    # ── soul_findings: rename/add/drop columns ───────────────────────────
    op.alter_column(
        "soul_findings", "detector", new_column_name="detector_id",
        existing_type=sa.String(100), type_=sa.String(50),
    )
    op.alter_column(
        "soul_findings", "poc_script", new_column_name="poc_code",
    )
    op.add_column(
        "soul_findings",
        sa.Column("finding_type", sa.String(30), server_default="violation"),
    )

    # Drop soul_findings columns the ORM no longer declares
    op.drop_column("soul_findings", "confidence")
    op.drop_column("soul_findings", "trigger_input")
    op.drop_column("soul_findings", "invariant_violated")
    op.drop_column("soul_findings", "exploit_chain_id")


def downgrade() -> None:
    # ── Reverse soul_findings changes ────────────────────────────────────
    op.add_column(
        "soul_findings",
        sa.Column("exploit_chain_id", sa.String(100), nullable=True),
    )
    op.add_column(
        "soul_findings",
        sa.Column("invariant_violated", sa.String(200), server_default=""),
    )
    op.add_column(
        "soul_findings",
        sa.Column("trigger_input", JSONB, server_default="{}"),
    )
    op.add_column(
        "soul_findings",
        sa.Column("confidence", sa.Float, server_default="0.0"),
    )
    op.drop_column("soul_findings", "finding_type")
    op.alter_column(
        "soul_findings", "poc_code", new_column_name="poc_script",
    )
    op.alter_column(
        "soul_findings", "detector_id", new_column_name="detector",
        existing_type=sa.String(50), type_=sa.String(100),
    )

    # ── Reverse soul_campaigns changes ───────────────────────────────────
    op.add_column(
        "soul_campaigns",
        sa.Column("engine_stats", JSONB, server_default="{}"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("total_phases", sa.Integer, server_default="18"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("current_phase_number", sa.Integer, server_default="0"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("phase", sa.String(50), server_default="initializing"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("findings_count", sa.Integer, server_default="0"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("branch_coverage_pct", sa.Float, server_default="0.0"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("coverage_pct", sa.Float, server_default="0.0"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("max_iterations", sa.Integer, server_default="50000"),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("chain", sa.String(30), nullable=True),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("contract_address", sa.String(42), nullable=True),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("repo_url", sa.Text, nullable=True),
    )
    op.add_column(
        "soul_campaigns",
        sa.Column("source_type", sa.String(30), nullable=True),
    )

    op.alter_column(
        "soul_campaigns", "duration_sec", new_column_name="duration_seconds"
    )
    op.alter_column(
        "soul_campaigns", "score", new_column_name="security_score"
    )
    op.alter_column(
        "soul_campaigns", "total_iterations", new_column_name="iterations_completed"
    )
    op.alter_column(
        "soul_campaigns", "source_code", new_column_name="contract_source"
    )

    op.drop_column("soul_campaigns", "result")
    op.drop_column("soul_campaigns", "unique_paths")
    op.drop_column("soul_campaigns", "corpus_size")
    op.drop_column("soul_campaigns", "mutation_stats")
    op.drop_column("soul_campaigns", "coverage")
    op.drop_column("soul_campaigns", "violations_count")
    op.drop_column("soul_campaigns", "bytecode")
    op.drop_column("soul_campaigns", "contract_name")

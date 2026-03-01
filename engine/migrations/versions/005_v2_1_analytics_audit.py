"""v2.1.0 — Analytics, audit log, and bridge-detection support.

Adds:
  - scan_analytics materialized-view-style table for pre-aggregated metrics
  - audit_logs table for compliance and security event tracking
  - Bridge-specific indices on findings for the new detector category
  - finding confidence column for detector-reported confidence scores
  - scan.engine_version column to track which engine produced results

Revision ID: 005
Revises: 004
Create Date: 2026-03-15
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── 1. Audit logs ────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("org_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),         # e.g. scan.created, finding.triaged, report.generated
        sa.Column("resource_type", sa.String(50), nullable=False),   # scan, finding, report, project, user
        sa.Column("resource_id", UUID(as_uuid=True), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),       # IPv4 or IPv6
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("details", JSONB, server_default="{}"),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_org_id", "audit_logs", ["org_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index(
        "ix_audit_logs_resource",
        "audit_logs",
        ["resource_type", "resource_id"],
    )

    # ── 2. Scan analytics (pre-aggregated daily metrics) ─────────────────
    op.create_table(
        "scan_analytics",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("date", sa.Date, nullable=False),
        sa.Column("total_scans", sa.Integer, server_default="0"),
        sa.Column("completed_scans", sa.Integer, server_default="0"),
        sa.Column("failed_scans", sa.Integer, server_default="0"),
        sa.Column("total_findings", sa.Integer, server_default="0"),
        sa.Column("critical_findings", sa.Integer, server_default="0"),
        sa.Column("high_findings", sa.Integer, server_default="0"),
        sa.Column("medium_findings", sa.Integer, server_default="0"),
        sa.Column("low_findings", sa.Integer, server_default="0"),
        sa.Column("avg_security_score", sa.Float, nullable=True),
        sa.Column("total_lines_scanned", sa.BigInteger, server_default="0"),
        sa.Column("avg_scan_duration_sec", sa.Float, nullable=True),
        sa.Column("unique_projects", sa.Integer, server_default="0"),
        sa.UniqueConstraint("org_id", "date", name="uq_scan_analytics_org_date"),
    )
    op.create_index("ix_scan_analytics_org_date", "scan_analytics", ["org_id", "date"])

    # ── 3. Add confidence to findings ────────────────────────────────────
    op.add_column(
        "findings",
        sa.Column("confidence", sa.Float, server_default="0.8"),
    )

    # ── 4. Add engine_version to scans ───────────────────────────────────
    op.add_column(
        "scans",
        sa.Column("engine_version", sa.String(20), server_default="2.1.0"),
    )

    # ── 5. Bridge category index on findings ─────────────────────────────
    op.create_index(
        "ix_findings_category",
        "findings",
        ["category"],
    )
    op.create_index(
        "ix_findings_severity",
        "findings",
        ["severity"],
    )

    # ── 6. Composite index for paginated queries ─────────────────────────
    op.create_index(
        "ix_findings_scan_severity",
        "findings",
        ["scan_id", "severity"],
    )
    op.create_index(
        "ix_scans_project_status",
        "scans",
        ["project_id", "status"],
    )

    # ── 7. Add confidence to soul_findings ───────────────────────────────
    op.add_column(
        "soul_findings",
        sa.Column("confidence", sa.Float, server_default="0.8"),
    )


def downgrade() -> None:
    op.drop_column("soul_findings", "confidence")
    op.drop_index("ix_scans_project_status", table_name="scans")
    op.drop_index("ix_findings_scan_severity", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_category", table_name="findings")
    op.drop_column("scans", "engine_version")
    op.drop_column("findings", "confidence")
    op.drop_table("scan_analytics")
    op.drop_index("ix_audit_logs_resource", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_table("audit_logs")

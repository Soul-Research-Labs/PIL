"""Initial schema — users, orgs, projects, scans, findings, reports

Revision ID: 001_initial
Revises: None
Create Date: 2025-01-01 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB


# revision identifiers
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Users ────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), unique=True, nullable=True),
        sa.Column("username", sa.String(100), unique=True, nullable=False),
        sa.Column("display_name", sa.String(200), nullable=True),
        sa.Column("avatar_url", sa.Text, nullable=True),
        sa.Column("github_id", sa.Integer, unique=True, nullable=True),
        sa.Column("github_access_token", sa.Text, nullable=True),
        sa.Column("wallet_address", sa.String(42), unique=True, nullable=True),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Organizations ────────────────────────────────────────────────────
    op.create_table(
        "organizations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(200), unique=True, nullable=False),
        sa.Column("logo_url", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Org Memberships ──────────────────────────────────────────────────
    op.create_table(
        "org_memberships",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("org_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("role", sa.String(20), default="viewer"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── API Keys ─────────────────────────────────────────────────────────
    op.create_table(
        "api_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Projects ─────────────────────────────────────────────────────────
    op.create_table(
        "projects",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("github_repo_url", sa.Text, nullable=True),
        sa.Column("github_installation_id", sa.Integer, nullable=True),
        sa.Column("contract_address", sa.String(42), nullable=True),
        sa.Column("chain", sa.String(30), nullable=True),
        sa.Column("auto_scan_on_push", sa.Boolean, default=True),
        sa.Column("scan_config", JSONB, default={}),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Scans ────────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("scan_type", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), default="pending"),
        sa.Column("trigger", sa.String(30), default="manual"),
        sa.Column("commit_sha", sa.String(40), nullable=True),
        sa.Column("branch", sa.String(200), nullable=True),
        sa.Column("pr_number", sa.Integer, nullable=True),
        sa.Column("security_score", sa.Float, nullable=True),
        sa.Column("threat_score", sa.Float, nullable=True),
        sa.Column("total_lines_scanned", sa.Integer, default=0),
        sa.Column("findings_count", sa.Integer, default=0),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", JSONB, default={}),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Findings ─────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), default="detected"),
        sa.Column("category", sa.String(100), default=""),
        sa.Column("cwe_id", sa.String(20), default=""),
        sa.Column("scwe_id", sa.String(20), default=""),
        sa.Column("file_path", sa.Text, nullable=False),
        sa.Column("start_line", sa.Integer, nullable=False),
        sa.Column("end_line", sa.Integer, nullable=False),
        sa.Column("code_snippet", sa.Text, default=""),
        sa.Column("data_flow", JSONB, default=[]),
        sa.Column("cvss_vector", sa.String(200), default=""),
        sa.Column("cvss_score", sa.Float, default=0.0),
        sa.Column("poc_script", sa.Text, nullable=True),
        sa.Column("poc_output", sa.Text, nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remediation", sa.Text, default=""),
        sa.Column("patch_diff", sa.Text, nullable=True),
        sa.Column("pr_url", sa.Text, nullable=True),
        sa.Column("gas_saved", sa.Integer, nullable=True),
        sa.Column("metadata", JSONB, default={}),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Reports ──────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("report_type", sa.String(30), default="full"),
        sa.Column("format", sa.String(10), default="pdf"),
        sa.Column("file_key", sa.Text, nullable=False),
        sa.Column("file_size_bytes", sa.Integer, default=0),
        sa.Column("is_published", sa.Boolean, default=False),
        sa.Column("public_url", sa.Text, nullable=True),
        sa.Column("public_slug", sa.String(100), unique=True, nullable=True),
        sa.Column("verification_hash", sa.String(64), nullable=True),
        sa.Column("custom_branding", JSONB, default={}),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── Indexes ──────────────────────────────────────────────────────────
    op.create_index("ix_scans_project_id", "scans", ["project_id"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_github_id", "users", ["github_id"])
    op.create_index("ix_projects_org_id", "projects", ["org_id"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("projects")
    op.drop_table("api_keys")
    op.drop_table("org_memberships")
    op.drop_table("organizations")
    op.drop_table("users")

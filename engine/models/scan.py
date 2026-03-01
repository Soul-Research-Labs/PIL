"""Project, scan, finding, and report models."""

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


class Project(Base, UUIDMixin, TimestampMixin):
    """A project encapsulates a codebase or smart contract to be scanned."""

    __tablename__ = "projects"

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Source info
    source_type: Mapped[str] = mapped_column(String(30), nullable=False)  # github_repo, contract_address, file_upload
    github_repo_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    github_installation_id: Mapped[int | None] = mapped_column(nullable=True)

    # Smart contract fields
    contract_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    chain: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Config
    auto_scan_on_push: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_config: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="projects")
    scans: Mapped[list["Scan"]] = relationship(back_populates="project", order_by="Scan.created_at.desc()")


class Scan(Base, UUIDMixin, TimestampMixin):
    """A single scan execution against a project."""

    __tablename__ = "scans"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(30), nullable=False)  # general, smart_contract, full
    status: Mapped[str] = mapped_column(String(20), default="pending")
    trigger: Mapped[str] = mapped_column(String(30), default="manual")  # manual, webhook, schedule

    # Git context
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(200), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(nullable=True)

    # Results
    security_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threat_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_lines_scanned: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Metadata
    metadata: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", order_by="Finding.severity")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan")


class Finding(Base, UUIDMixin, TimestampMixin):
    """A security finding or vulnerability detected during a scan."""

    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="detected")
    category: Mapped[str] = mapped_column(String(100), default="")

    # Classification
    cwe_id: Mapped[str] = mapped_column(String(20), default="")
    scwe_id: Mapped[str] = mapped_column(String(20), default="")  # OWASP SCWE for smart contracts

    # Location
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    code_snippet: Mapped[str] = mapped_column(Text, default="")

    # Data flow (for taint analysis)
    data_flow: Mapped[dict] = mapped_column(JSONB, default=list)

    # CVSS
    cvss_vector: Mapped[str] = mapped_column(String(200), default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Verification (PoC)
    poc_script: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Remediation
    remediation: Mapped[str] = mapped_column(Text, default="")
    patch_diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    pr_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Gas optimization (smart contracts)
    gas_saved: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Extra metadata
    metadata: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="findings")


class Report(Base, UUIDMixin, TimestampMixin):
    """Generated audit report for a scan."""

    __tablename__ = "reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    report_type: Mapped[str] = mapped_column(String(30), default="full")  # full, gas_only, executive
    format: Mapped[str] = mapped_column(String(10), default="pdf")

    # Storage
    file_key: Mapped[str] = mapped_column(Text, nullable=False)  # S3 key
    file_size_bytes: Mapped[int] = mapped_column(Integer, default=0)

    # Publishing
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    public_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    public_slug: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)
    verification_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Customization
    custom_branding: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="reports")

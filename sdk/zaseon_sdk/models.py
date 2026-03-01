"""Pydantic models for ZASEON SDK responses."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    """Scan execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Finding(BaseModel):
    """A single vulnerability finding."""

    id: str = ""
    title: str
    severity: Severity
    category: str = ""
    description: str = ""
    recommendation: str = ""
    file_path: str = ""
    line_start: int | None = None
    line_end: int | None = None
    confidence: float = 0.0
    detector: str = ""
    exploit_available: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    """Configuration for a scan request."""

    source_code: str | None = None
    contract_name: str | None = None
    github_url: str | None = None
    address: str | None = None
    chain: str = "ethereum"
    mode: str = "standard"  # quick | standard | deep
    enable_symbolic: bool = False
    enable_llm: bool = True
    enable_verification: bool = True
    severity_threshold: Severity | None = None
    max_duration: int | None = None


class ScanResult(BaseModel):
    """Result of a completed scan."""

    scan_id: str
    status: ScanStatus
    security_score: float | None = None
    findings: list[Finding] = Field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    duration_seconds: float | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class QuickScanResult(BaseModel):
    """Result of a quick scan (synchronous)."""

    findings: list[Finding] = Field(default_factory=list)
    security_score: float | None = None
    scan_duration: float | None = None
    contract_name: str = ""


class AnalyticsSummary(BaseModel):
    """Analytics summary data."""

    total_scans: int = 0
    avg_security_score: float | None = None
    total_findings: int = 0
    mttr_hours: float | None = None
    scan_volume: list[dict[str, Any]] = Field(default_factory=list)
    score_trend: list[dict[str, Any]] = Field(default_factory=list)


class CursorPage(BaseModel):
    """Paginated response with cursor-based pagination."""

    items: list[dict[str, Any]] = Field(default_factory=list)
    next_cursor: str | None = None
    prev_cursor: str | None = None
    has_more: bool = False
    total_count: int | None = None

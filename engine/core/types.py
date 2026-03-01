"""Shared enums and types used across the engine."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────


class ScanType(str, enum.Enum):
    """Type of scan being performed."""

    SMART_CONTRACT = "smart_contract"


class ScanStatus(str, enum.Enum):
    """Status of a scan."""

    PENDING = "pending"
    INGESTING = "ingesting"
    ANALYZING = "analyzing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    """Vulnerability severity level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    GAS = "gas"


class FindingStatus(str, enum.Enum):
    """Status of a finding through the verification pipeline."""

    DETECTED = "detected"
    VERIFYING = "verifying"
    CONFIRMED = "confirmed"
    DISCARDED = "discarded"
    PATCHED = "patched"


class Chain(str, enum.Enum):
    """Supported EVM chains."""

    ETHEREUM = "ethereum"
    POLYGON = "polygon"
    BSC = "bsc"
    AVALANCHE = "avalanche"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BASE = "base"
    ZKSYNC = "zksync"
    LINEA = "linea"
    FANTOM = "fantom"
    GNOSIS = "gnosis"
    CELO = "celo"
    MOONBEAM = "moonbeam"
    SCROLL = "scroll"


class SourceType(str, enum.Enum):
    """How the code was provided for scanning."""

    GITHUB_REPO = "github_repo"
    CONTRACT_ADDRESS = "contract_address"
    FILE_UPLOAD = "file_upload"


# ── Shared Schemas ───────────────────────────────────────────────────────────


class Location(BaseModel):
    """Code location of a finding."""

    file_path: str
    start_line: int
    end_line: int
    start_col: int | None = None
    end_col: int | None = None
    snippet: str = ""


class CVSSVector(BaseModel):
    """CVSS 3.1 vector breakdown."""

    vector_string: str = ""
    base_score: float = 0.0
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""


class GasOptimization(BaseModel):
    """Gas optimization suggestion for smart contracts."""

    location: Location
    description: str
    suggestion: str
    estimated_gas_saved: int = 0
    category: str = ""


class FindingSchema(BaseModel):
    """Finding schema for smart contract vulnerabilities."""

    id: str = ""
    title: str
    description: str
    severity: Severity
    status: FindingStatus = FindingStatus.DETECTED
    confidence: float = 1.0
    category: str = ""
    cwe_id: str = ""
    scwe_id: str = ""
    location: Location
    data_flow: list[Location] = Field(default_factory=list)
    cvss: CVSSVector = Field(default_factory=CVSSVector)
    poc_script: str = ""
    poc_output: str = ""
    remediation: str = ""
    patch_diff: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime | None = None
    verified_at: datetime | None = None


class ScanResult(BaseModel):
    """Result of a completed scan."""

    scan_id: str
    scan_type: ScanType
    status: ScanStatus
    findings: list[FindingSchema] = Field(default_factory=list)
    gas_optimizations: list[GasOptimization] = Field(default_factory=list)
    security_score: float = 100.0
    threat_score: float = 0.0
    total_lines_scanned: int = 0
    scan_duration_seconds: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityScore(BaseModel):
    """Security score calculation."""

    score: float = 100.0
    threat_score: float = 0.0
    breakdown: dict[str, int] = Field(default_factory=dict)

    @staticmethod
    def calculate(findings: list[FindingSchema]) -> "SecurityScore":
        """Calculate security score from findings."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 1,
            Severity.GAS: 0,
        }

        breakdown: dict[str, int] = {}
        penalty = 0.0

        for finding in findings:
            if finding.status == FindingStatus.DISCARDED:
                continue
            sev_name = finding.severity.value
            breakdown[sev_name] = breakdown.get(sev_name, 0) + 1
            penalty += weights.get(finding.severity, 0)

        score = max(0.0, min(100.0, 100.0 - penalty))
        threat_score = 100.0 - score

        return SecurityScore(
            score=score,
            threat_score=threat_score,
            breakdown=breakdown,
        )

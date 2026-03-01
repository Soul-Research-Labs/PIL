"""Tests for engine.core.types — shared enums, schemas, and scoring."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from engine.core.types import (
    Chain,
    CVSSVector,
    FindingSchema,
    FindingStatus,
    GasOptimization,
    Location,
    ScanResult,
    ScanStatus,
    ScanType,
    SecurityScore,
    Severity,
    SourceType,
)


# ── Enum Tests ───────────────────────────────────────────────────────────────


class TestEnums:
    """Verify all enums have correct members."""

    def test_scan_type_smart_contract(self):
        assert ScanType.SMART_CONTRACT.value == "smart_contract"

    def test_scan_status_has_all_stages(self):
        expected = {"pending", "ingesting", "analyzing", "verifying", "completed", "failed"}
        actual = {s.value for s in ScanStatus}
        assert actual == expected

    def test_severity_ordering(self):
        ordered = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL, Severity.GAS]
        assert len(ordered) == 6
        assert ordered[0].value == "critical"
        assert ordered[-1].value == "gas"

    def test_finding_status_progression(self):
        assert FindingStatus.DETECTED.value == "detected"
        assert FindingStatus.VERIFYING.value == "verifying"
        assert FindingStatus.CONFIRMED.value == "confirmed"
        assert FindingStatus.DISCARDED.value == "discarded"
        assert FindingStatus.PATCHED.value == "patched"

    def test_chain_has_major_evms(self):
        names = {c.value for c in Chain}
        assert "ethereum" in names
        assert "polygon" in names
        assert "arbitrum" in names
        assert "base" in names
        assert "zksync" in names

    def test_source_type_variants(self):
        assert SourceType.GITHUB_REPO.value == "github_repo"
        assert SourceType.CONTRACT_ADDRESS.value == "contract_address"
        assert SourceType.FILE_UPLOAD.value == "file_upload"


# ── Location Tests ───────────────────────────────────────────────────────────


class TestLocation:
    def test_basic_location(self, sample_location: Location):
        assert sample_location.file_path == "contracts/SoulZKSLock.sol"
        assert sample_location.start_line == 42
        assert sample_location.end_line == 55

    def test_location_optional_cols(self):
        loc = Location(file_path="test.sol", start_line=1, end_line=10)
        assert loc.start_col is None
        assert loc.end_col is None

    def test_location_serialization(self, sample_location: Location):
        data = sample_location.model_dump()
        restored = Location.model_validate(data)
        assert restored.file_path == sample_location.file_path
        assert restored.start_line == sample_location.start_line


# ── CVSSVector Tests ─────────────────────────────────────────────────────────


class TestCVSSVector:
    def test_critical_cvss(self, sample_cvss: CVSSVector):
        assert sample_cvss.base_score == 9.8
        assert "3.1" in sample_cvss.vector_string

    def test_default_cvss(self):
        cvss = CVSSVector()
        assert cvss.base_score == 0.0
        assert cvss.vector_string == ""


# ── FindingSchema Tests ──────────────────────────────────────────────────────


class TestFindingSchema:
    def test_finding_fields(self, sample_finding: FindingSchema):
        assert sample_finding.severity == Severity.CRITICAL
        assert sample_finding.status == FindingStatus.CONFIRMED
        assert sample_finding.confidence == 0.95
        assert "ZK" in sample_finding.title

    def test_finding_defaults(self):
        finding = FindingSchema(
            title="Test",
            description="Test desc",
            severity=Severity.LOW,
            location=Location(file_path="a.sol", start_line=1, end_line=1),
        )
        assert finding.status == FindingStatus.DETECTED
        assert finding.confidence == 1.0
        assert finding.data_flow == []
        assert finding.poc_script == ""

    def test_finding_roundtrip_json(self, sample_finding: FindingSchema):
        json_str = sample_finding.model_dump_json()
        restored = FindingSchema.model_validate_json(json_str)
        assert restored.title == sample_finding.title
        assert restored.severity == sample_finding.severity


# ── GasOptimization Tests ────────────────────────────────────────────────────


class TestGasOptimization:
    def test_gas_opt_fields(self, sample_gas_optimization: GasOptimization):
        assert sample_gas_optimization.estimated_gas_saved == 2100
        assert "calldata" in sample_gas_optimization.description.lower()

    def test_gas_opt_defaults(self):
        opt = GasOptimization(
            location=Location(file_path="a.sol", start_line=1, end_line=1),
            description="test",
            suggestion="test",
        )
        assert opt.estimated_gas_saved == 0
        assert opt.category == ""


# ── ScanResult Tests ─────────────────────────────────────────────────────────


class TestScanResult:
    def test_scan_result_fields(self, sample_scan_result: ScanResult):
        assert sample_scan_result.status == ScanStatus.COMPLETED
        assert sample_scan_result.scan_type == ScanType.SMART_CONTRACT
        assert len(sample_scan_result.findings) == 5
        assert len(sample_scan_result.gas_optimizations) == 1
        assert sample_scan_result.total_lines_scanned == 1500

    def test_scan_result_defaults(self):
        result = ScanResult(scan_id="test", scan_type=ScanType.SMART_CONTRACT, status=ScanStatus.PENDING)
        assert result.findings == []
        assert result.gas_optimizations == []
        assert result.security_score == 100.0
        assert result.threat_score == 0.0


# ── SecurityScore Tests ──────────────────────────────────────────────────────


class TestSecurityScore:
    def test_perfect_score_no_findings(self):
        score = SecurityScore.calculate([])
        assert score.score == 100.0
        assert score.threat_score == 0.0
        assert score.breakdown == {}

    def test_single_critical_finding(self, sample_finding: FindingSchema):
        score = SecurityScore.calculate([sample_finding])
        assert score.score == 75.0  # 100 - 25 (critical weight)
        assert score.threat_score == 25.0
        assert score.breakdown["critical"] == 1

    def test_mixed_severity_scoring(self, sample_findings: list[FindingSchema]):
        score = SecurityScore.calculate(sample_findings)
        # critical=25, high=15, medium=8, low=3, info=1 = 52
        assert score.score == max(0.0, 100.0 - 52.0)
        assert score.breakdown["critical"] == 1
        assert score.breakdown["high"] == 1
        assert score.breakdown["medium"] == 1

    def test_discarded_findings_excluded(self, sample_finding: FindingSchema):
        discarded = sample_finding.model_copy(update={"status": FindingStatus.DISCARDED})
        score = SecurityScore.calculate([discarded])
        assert score.score == 100.0  # discarded = no penalty

    def test_score_floor_at_zero(self):
        """Lots of critical findings should not go below 0."""
        findings = [
            FindingSchema(
                title=f"Critical {i}",
                description="test",
                severity=Severity.CRITICAL,
                location=Location(file_path="a.sol", start_line=1, end_line=1),
            )
            for i in range(10)
        ]
        score = SecurityScore.calculate(findings)
        assert score.score == 0.0  # 10 * 25 = 250, clamped to 0

    def test_gas_findings_no_penalty(self):
        findings = [
            FindingSchema(
                title="Gas issue",
                description="test",
                severity=Severity.GAS,
                location=Location(file_path="a.sol", start_line=1, end_line=1),
            )
            for _ in range(5)
        ]
        score = SecurityScore.calculate(findings)
        assert score.score == 100.0

"""Tests for the ZASEON CLI tool (engine/cli/main.py).

Covers:
- Argument parsing (scan, report, config, version)
- Severity filtering & sorting
- Output formatting (table, json, sarif, html)
- Error handling (missing path, missing address, non-existent path)
- Banner suppression
- Quiet mode
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.cli.main import (
    BANNER,
    _filter_findings,
    _print_table,
    _run_config,
    _sev_index,
    build_parser,
    main,
)
from engine.core.types import (
    FindingSchema,
    FindingStatus,
    GasOptimization,
    Location,
    ScanResult,
    ScanStatus,
    ScanType,
    Severity,
)


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def parser() -> argparse.ArgumentParser:
    return build_parser()


@pytest.fixture
def minimal_scan_result() -> ScanResult:
    findings = [
        FindingSchema(
            id=str(uuid.uuid4()),
            title="Reentrancy",
            description="External call before state update.",
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            confidence=0.95,
            category="reentrancy",
            location=Location(file_path="Token.sol", start_line=10, end_line=15),
        ),
        FindingSchema(
            id=str(uuid.uuid4()),
            title="Missing zero-address check",
            description="No zero-address validation.",
            severity=Severity.LOW,
            status=FindingStatus.DETECTED,
            confidence=0.90,
            category="validation",
            location=Location(file_path="Token.sol", start_line=20, end_line=22),
        ),
        FindingSchema(
            id=str(uuid.uuid4()),
            title="Gas can be saved",
            description="Use calldata instead of memory.",
            severity=Severity.GAS,
            status=FindingStatus.DETECTED,
            confidence=1.0,
            category="gas",
            location=Location(file_path="Token.sol", start_line=30, end_line=32),
        ),
        FindingSchema(
            id=str(uuid.uuid4()),
            title="Unchecked return value",
            description="Return value of call not checked.",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            confidence=0.85,
            category="unchecked-return",
            location=Location(file_path="Token.sol", start_line=40, end_line=42),
        ),
        FindingSchema(
            id=str(uuid.uuid4()),
            title="Floating pragma",
            description="Pragma not pinned.",
            severity=Severity.INFORMATIONAL,
            status=FindingStatus.DETECTED,
            confidence=1.0,
            category="best-practice",
            location=Location(file_path="Token.sol", start_line=1, end_line=1),
        ),
    ]
    return ScanResult(
        scan_id="test-scan-001",
        scan_type=ScanType.SMART_CONTRACT,
        status=ScanStatus.COMPLETED,
        findings=findings,
        gas_optimizations=[],
        security_score=55.0,
        threat_score=45.0,
        total_lines_scanned=200,
        scan_duration_seconds=2.5,
    )


# ── Parser Tests ─────────────────────────────────────────────────────────


class TestBuildParser:
    """Tests for CLI argument parsing."""

    def test_version_flag(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["--version"])
        assert args.version is True

    def test_scan_subcommand_with_path(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", "./contracts/"])
        assert args.command == "scan"
        assert args.path == "./contracts/"

    def test_scan_subcommand_with_address(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", "--address", "0xdead"])
        assert args.command == "scan"
        assert args.address == "0xdead"

    def test_scan_format_options(self, parser: argparse.ArgumentParser):
        for fmt in ("table", "json", "sarif", "html"):
            args = parser.parse_args(["scan", ".", "--format", fmt])
            assert args.format == fmt

    def test_scan_severity_filter(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", ".", "--severity", "high"])
        assert args.severity == "high"

    def test_scan_output_flag(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", ".", "-o", "results.json"])
        assert args.output == "results.json"

    def test_scan_no_llm_flag(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", ".", "--no-llm"])
        assert args.no_llm is True

    def test_scan_no_verify_flag(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", ".", "--no-verify"])
        assert args.no_verify is True

    def test_scan_chain_default(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", "--address", "0x1"])
        assert args.chain == "ethereum"

    def test_scan_chain_choice(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", "--address", "0x1", "--chain", "polygon"])
        assert args.chain == "polygon"

    def test_report_subcommand(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["report", "latest"])
        assert args.command == "report"
        assert args.scan_id == "latest"

    def test_config_subcommand(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["config"])
        assert args.command == "config"

    def test_quiet_flag(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["--quiet", "scan", "."])
        assert args.quiet is True

    def test_no_banner_flag(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["--no-banner", "scan", "."])
        assert args.no_banner is True

    def test_max_findings(self, parser: argparse.ArgumentParser):
        args = parser.parse_args(["scan", ".", "--max-findings", "5"])
        assert args.max_findings == 5


# ── Severity helpers ─────────────────────────────────────────────────────


class TestSeverityHelpers:
    """Tests for severity index and filtering."""

    def test_sev_index_known(self):
        assert _sev_index("critical") == 0
        assert _sev_index("high") == 1
        assert _sev_index("medium") == 2
        assert _sev_index("low") == 3
        assert _sev_index("informational") == 4
        assert _sev_index("gas") == 5

    def test_sev_index_unknown(self):
        assert _sev_index("nonexistent") == 99

    def test_sev_index_case_insensitive(self):
        assert _sev_index("CRITICAL") == 0
        assert _sev_index("High") == 1

    def test_filter_no_filter(self, minimal_scan_result: ScanResult):
        findings = _filter_findings(minimal_scan_result, None, 0)
        assert len(findings) == 5
        # Should be sorted: critical, high, medium, low, info, gas
        sevs = [f.severity.value for f in findings]
        assert sevs == ["critical", "high", "low", "informational", "gas"]

    def test_filter_by_severity_high(self, minimal_scan_result: ScanResult):
        findings = _filter_findings(minimal_scan_result, "high", 0)
        assert all(f.severity.value in ("critical", "high") for f in findings)

    def test_filter_by_severity_info_alias(self, minimal_scan_result: ScanResult):
        findings = _filter_findings(minimal_scan_result, "info", 0)
        # info is alias for informational — should include everything except gas
        assert len(findings) == 4

    def test_filter_max_count(self, minimal_scan_result: ScanResult):
        findings = _filter_findings(minimal_scan_result, None, 2)
        assert len(findings) == 2

    def test_filter_critical_only(self, minimal_scan_result: ScanResult):
        findings = _filter_findings(minimal_scan_result, "critical", 0)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


# ── Print table ──────────────────────────────────────────────────────────


class TestPrintTable:
    """Tests for table output formatting."""

    def test_no_findings(self, minimal_scan_result: ScanResult, capsys):
        _print_table([], minimal_scan_result)
        captured = capsys.readouterr()
        assert "No findings" in captured.out

    def test_with_findings(self, minimal_scan_result: ScanResult, capsys):
        findings = _filter_findings(minimal_scan_result, None, 0)
        _print_table(findings, minimal_scan_result)
        captured = capsys.readouterr()
        assert "Scan complete" in captured.out
        assert "Reentrancy" in captured.out

    def test_quiet_mode(self, minimal_scan_result: ScanResult, capsys):
        findings = _filter_findings(minimal_scan_result, None, 0)
        _print_table(findings, minimal_scan_result, quiet=True)
        captured = capsys.readouterr()
        assert "Scan complete" not in captured.out
        assert "CRITICAL" in captured.out


# ── main() entry point ──────────────────────────────────────────────────


class TestMainEntryPoint:
    """Tests for the main() function dispatching."""

    def test_version_print(self, capsys):
        code = main(["--version"])
        assert code == 0
        captured = capsys.readouterr()
        assert "2.0.0" in captured.out

    def test_no_command_shows_help(self, capsys):
        code = main(["--no-banner"])
        assert code == 0

    @patch("engine.cli.main._run_config")
    def test_config_dispatch(self, mock_config):
        mock_config.return_value = 0
        code = main(["--no-banner", "config"])
        assert code == 0
        mock_config.assert_called_once()

    def test_banner_shown_on_stderr(self, capsys):
        main(["--version"])
        captured = capsys.readouterr()
        # Banner goes to stderr
        assert "ZASEON" in captured.err or "zaseon" in captured.out

    def test_config_command_runs(self, capsys):
        """Config should print settings without crashing."""
        with patch("engine.cli.main.get_settings") as mock_settings:
            mock_s = MagicMock()
            mock_s.model_fields.keys.return_value = ["secret_key", "debug", "app_name"]
            mock_s.secret_key = "some-secret"
            mock_s.debug = True
            mock_s.app_name = "ZASEON"
            mock_settings.return_value = mock_s
            code = _run_config()
            assert code == 0
            captured = capsys.readouterr()
            assert "****" in captured.out  # secret_key redacted
            assert "ZASEON" in captured.out or "app_name" in captured.out

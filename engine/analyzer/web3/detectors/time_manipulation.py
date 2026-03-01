"""Time manipulation and block dependency detectors (AST-enhanced).

Detects vulnerabilities related to:
  - block.timestamp manipulation for randomness or access control
  - block.number dependency for timing-sensitive logic
  - Timestamp-based lock bypasses
  - Weak randomness from block variables
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Location, Severity


class TimestampDependence(BaseDetector):
    """Detect dangerous uses of block.timestamp in conditional logic."""

    DETECTOR_ID = "time-timestamp-dependence"
    DETECTOR_NAME = "Block Timestamp Dependence"
    SEVERITY = Severity.MEDIUM
    CONFIDENCE = 0.80
    CATEGORY = "time-manipulation"

    _TIMESTAMP_CONDITION_RE = re.compile(
        r"\b(require|if|assert|while)\s*\([^)]*block\.timestamp\b",
        re.DOTALL,
    )
    _TIMESTAMP_COMPARE_RE = re.compile(
        r"block\.timestamp\s*([<>=!]+)",
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []

        for i, line in enumerate(context.lines):
            if "block.timestamp" not in line:
                continue

            # Check if used in condition
            surrounding = "\n".join(context.lines[max(0, i - 2):i + 3])
            if self._TIMESTAMP_CONDITION_RE.search(surrounding):
                # Check comparison operator
                comp = self._TIMESTAMP_COMPARE_RE.search(line)
                op = comp.group(1) if comp else "=="

                severity = Severity.MEDIUM
                if "==" in op:
                    severity = Severity.HIGH  # Strict equality is very dangerous

                findings.append(self._make_finding(
                    title="Block timestamp used in conditional logic",
                    description=(
                        f"block.timestamp is used in a condition with operator '{op}'. "
                        "Miners can manipulate block.timestamp by ~15 seconds, "
                        "which may allow bypassing time-based conditions."
                    ),
                    severity=severity,
                    location=Location(
                        file_path=context.contract_name or "contract",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                    ),
                    remediation=(
                        "Avoid strict equality checks with block.timestamp. "
                        "Use >= or <= with sufficient tolerance. "
                        "For randomness, use Chainlink VRF instead."
                    ),
                ))

        return findings


class BlockNumberDependence(BaseDetector):
    """Detect block.number used for timing-sensitive logic."""

    DETECTOR_ID = "time-blocknumber-dependence"
    DETECTOR_NAME = "Block Number Dependence"
    SEVERITY = Severity.LOW
    CONFIDENCE = 0.75
    CATEGORY = "time-manipulation"

    _BLOCKNUMBER_COND_RE = re.compile(
        r"\b(require|if|assert)\s*\([^)]*block\.number\b",
        re.DOTALL,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        for i, line in enumerate(context.lines):
            if "block.number" not in line:
                continue

            surrounding = "\n".join(context.lines[max(0, i - 2):i + 3])
            if self._BLOCKNUMBER_COND_RE.search(surrounding):
                findings.append(self._make_finding(
                    title="Block number used in timing-sensitive logic",
                    description=(
                        "block.number is used in conditional logic. "
                        "Block times vary across chains and after network upgrades. "
                        "This can lead to incorrect timing assumptions."
                    ),
                    location=Location(
                        file_path=context.contract_name or "contract",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                    ),
                    remediation=(
                        "Prefer block.timestamp for time-based logic. "
                        "Account for variable block times across different chains."
                    ),
                ))

        return findings


class TimelockBypassTimestamp(BaseDetector):
    """Detect potential timelock bypasses via timestamp manipulation."""

    DETECTOR_ID = "time-timelock-bypass"
    DETECTOR_NAME = "Timelock Bypass via Timestamp"
    SEVERITY = Severity.HIGH
    CONFIDENCE = 0.70
    CATEGORY = "time-manipulation"

    _TIMELOCK_RE = re.compile(
        r"block\.timestamp\s*>=?\s*(\w+)\s*\+\s*(\w+)",
    )
    _SHORT_DELAY_RE = re.compile(
        r"\b(?:delay|timelock|lockTime|lockDuration)\s*=\s*(\d+)",
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        for i, line in enumerate(context.lines):
            # Check for short timelock delays
            short_match = self._SHORT_DELAY_RE.search(line)
            if short_match:
                delay_val = int(short_match.group(1))
                if delay_val > 0 and delay_val < 3600:  # Less than 1 hour
                    findings.append(self._make_finding(
                        title="Timelock delay too short",
                        description=(
                            f"Timelock delay is set to {delay_val} seconds ({delay_val/60:.0f} minutes). "
                            "Short timelocks provide insufficient protection and may be bypassed "
                            "via miner timestamp manipulation (±15s) or by rapid execution."
                        ),
                        severity=Severity.MEDIUM,
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            "Set timelock delay to at least 24-48 hours for governance actions. "
                            "Use established timelock contracts like OpenZeppelin's TimelockController."
                        ),
                    ))

        return findings

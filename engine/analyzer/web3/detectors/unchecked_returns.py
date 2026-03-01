"""Unchecked return value detectors — SCWE-048."""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity, Location


class UncheckedLowLevelCallDetector(BaseDetector):
    """Detect unchecked low-level call return values."""

    DETECTOR_ID = "SCWE-048-001"
    NAME = "Unchecked Low-Level Call"
    DESCRIPTION = "Low-level call return value not checked — silent failure"
    SCWE_ID = "SCWE-048"
    CWE_ID = "CWE-252"
    SEVERITY = Severity.HIGH
    CATEGORY = "unchecked_returns"

    LOW_LEVEL_CALLS = [".call(", ".call{", ".send(", ".staticcall("]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        lines = context.source_code.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for call in self.LOW_LEVEL_CALLS:
                if call in stripped:
                    if not self._is_return_checked(stripped, lines, i):
                        findings.append(self._make_finding(
                            title=f"Unchecked return value from low-level {call.split('(')[0]}",
                            description=(
                                f"The return value of `{call.rstrip('(')}` is not checked. "
                                "Failed calls will not revert, leading to silent loss of funds."
                            ),
                            location=Location(file="contract.sol", start_line=i, end_line=i, snippet=stripped),
                            remediation="Check the return value: `(bool success, ) = addr.call{value: amount}(\"\");` and `require(success);`",
                        ))
                    break
        return findings

    def _is_return_checked(self, line: str, lines: list[str], line_num: int) -> bool:
        # Pattern: (bool success,...) = ...
        if re.match(r"\(?bool\s+\w+", line):
            return True
        if line.startswith("(bool"):
            return True
        # Check next line for require
        if line_num < len(lines):
            next_line = lines[line_num].strip()
            if "require(" in next_line:
                return True
        # If inside require
        if "require(" in line:
            return True
        return False


class UncheckedTransferDetector(BaseDetector):
    """Detect unchecked ERC20 transfer/transferFrom return values."""

    DETECTOR_ID = "SCWE-048-002"
    NAME = "Unchecked ERC20 Transfer"
    DESCRIPTION = "ERC20 transfer return value not checked — tokens may not move"
    SCWE_ID = "SCWE-048"
    CWE_ID = "CWE-252"
    SEVERITY = Severity.HIGH
    CATEGORY = "unchecked_returns"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        lines = context.source_code.split("\n")

        # Check if SafeERC20 is imported — if so, likely safe
        uses_safe_erc20 = "SafeERC20" in context.source_code or "safeTransfer" in context.source_code

        if uses_safe_erc20:
            return findings

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Bare transfer / transferFrom without require
            if re.search(r"\.\s*transfer(From)?\s*\(", stripped):
                if "require(" not in stripped and "assert(" not in stripped:
                    if not stripped.startswith("bool") and not stripped.startswith("require"):
                        # Skip ETH transfers (address.transfer())
                        if ".transfer(" in stripped:
                            match = re.search(r"(\w+)\.transfer\(", stripped)
                            if match:
                                target = match.group(1)
                                if target in ("msg", "payable"):
                                    continue
                        findings.append(self._make_finding(
                            title="Unchecked ERC20 transfer return value",
                            description=(
                                "The return value of transfer/transferFrom is not checked. "
                                "Some ERC20 tokens (like USDT) don't return bool, "
                                "and others may return false instead of reverting."
                            ),
                            location=Location(file="contract.sol", start_line=i, end_line=i, snippet=stripped),
                            remediation="Use OpenZeppelin's SafeERC20: `token.safeTransfer(to, amount)` or wrap in require().",
                        ))
        return findings


class UncheckedApproveDetector(BaseDetector):
    """Detect unchecked ERC20 approve return values."""

    DETECTOR_ID = "SCWE-048-003"
    NAME = "Unchecked ERC20 Approve"
    DESCRIPTION = "ERC20 approve return value not checked"
    SCWE_ID = "SCWE-048"
    CWE_ID = "CWE-252"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "unchecked_returns"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        lines = context.source_code.split("\n")

        if "SafeERC20" in context.source_code or "safeApprove" in context.source_code:
            return findings

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if re.search(r"\.\s*approve\s*\(", stripped):
                if "require(" not in stripped and not stripped.startswith("bool"):
                    findings.append(self._make_finding(
                        title="Unchecked ERC20 approve return value",
                        description=(
                            "The return value of approve() is not checked. "
                            "Some tokens (like USDT) require allowance to be zero before setting a new value."
                        ),
                        location=Location(file="contract.sol", start_line=i, end_line=i, snippet=stripped),
                        remediation="Use SafeERC20's `safeIncreaseAllowance` / `forceApprove`, or reset to 0 first.",
                    ))
        return findings

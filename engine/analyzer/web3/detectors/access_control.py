"""Access control detectors — SCWE-016, SCWE-017, SCWE-018, SCWE-049, SCWE-050.

Detect missing or insufficient authorization checks, tx.origin misuse,
unprotected withdrawals, and unprotected selfdestruct.
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class MissingAccessControlDetector(BaseDetector):
    """Detect public/external functions that modify state without access control."""

    DETECTOR_ID = "SCWE-016-001"
    NAME = "Missing Access Control"
    DESCRIPTION = (
        "Detects public or external functions that modify critical state variables "
        "without any access control modifiers (onlyOwner, onlyRole, etc.)."
    )
    SCWE_ID = "SCWE-016"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.HIGH
    CATEGORY = "access_control"

    # Common access control modifiers
    ACCESS_MODIFIERS = {
        "onlyOwner", "onlyAdmin", "onlyRole", "onlyMinter",
        "onlyGovernance", "onlyOperator", "onlyAuthorized",
        "whenNotPaused", "nonReentrant", "auth", "restricted",
    }

    # Critical state-changing operations
    CRITICAL_OPERATIONS = {
        "selfdestruct", "delegatecall", "transfer(", ".call{value:",
        "mint(", "burn(", "pause(", "unpause(", "upgrade",
        "setOwner", "transferOwnership", "renounceOwnership",
    }

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Parse functions
        func_pattern = re.compile(
            r'function\s+(\w+)\s*\(([^)]*)\)\s+((?:public|external).*?){'
        , re.DOTALL)

        for match in func_pattern.finditer(source):
            func_name = match.group(1)
            modifiers_str = match.group(3)

            # Skip view/pure functions
            if "view" in modifiers_str or "pure" in modifiers_str:
                continue

            # Check for access control modifiers
            has_access_control = any(
                mod in modifiers_str for mod in self.ACCESS_MODIFIERS
            )

            if has_access_control:
                continue

            # Check for require(msg.sender == ...) inside the function
            func_start = match.start()
            # Find approximate function body (rough heuristic)
            brace_count = 0
            func_body = ""
            started = False
            for char in source[func_start:]:
                if char == "{":
                    brace_count += 1
                    started = True
                elif char == "}":
                    brace_count -= 1
                func_body += char
                if started and brace_count == 0:
                    break

            has_sender_check = bool(re.search(
                r'require\s*\(\s*msg\.sender\s*==|'
                r'if\s*\(\s*msg\.sender\s*!=|'
                r'_checkOwner|_checkRole',
                func_body,
            ))

            if has_sender_check:
                continue

            # Check if function performs critical operations
            has_critical_op = any(op in func_body for op in self.CRITICAL_OPERATIONS)

            if not has_critical_op:
                continue

            # Find line number
            line_no = source[:match.start()].count("\n") + 1
            snippet = "\n".join(
                lines[max(0, line_no - 1):min(len(lines), line_no + 4)]
            )

            findings.append(self._make_finding(
                title=f"Missing access control on `{func_name}`",
                description=(
                    f"The function `{func_name}` is public/external and performs "
                    "critical state-changing operations without any access control. "
                    "Any external account or contract can call this function."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no,
                end_line=line_no + 3,
                snippet=snippet,
                remediation=(
                    "Add access control to this function:\n"
                    "```solidity\n"
                    f"function {func_name}(...) external onlyOwner {{\n"
                    "    // ...\n"
                    "}\n```\n"
                    "Or use OpenZeppelin's AccessControl:\n"
                    "```solidity\n"
                    f'function {func_name}(...) external onlyRole(ADMIN_ROLE) {{ ... }}\n'
                    "```"
                ),
            ))

        return findings


class TxOriginDetector(BaseDetector):
    """Detect use of tx.origin for authorization."""

    DETECTOR_ID = "SCWE-018-001"
    NAME = "tx.origin Authorization"
    DESCRIPTION = (
        "Detects the use of tx.origin for authorization checks. tx.origin returns "
        "the original sender of a transaction, which can be exploited through "
        "phishing attacks where a malicious contract tricks users into calling it."
    )
    SCWE_ID = "SCWE-018"
    CWE_ID = "CWE-477"
    SEVERITY = Severity.HIGH
    CATEGORY = "access_control"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        pattern = re.compile(r'tx\.origin')

        for i, line in enumerate(lines):
            if pattern.search(line):
                # Check if it's used in a comparison (authorization check)
                if re.search(r'(require|assert|if)\s*\(.*tx\.origin', line):
                    snippet = "\n".join(
                        lines[max(0, i - 1):min(len(lines), i + 2)]
                    )
                    findings.append(self._make_finding(
                        title="Use of tx.origin for authorization",
                        description=(
                            "tx.origin is used for authorization, which is vulnerable to "
                            "phishing attacks. A malicious contract can trick a user into "
                            "calling it, and then call the vulnerable contract with the "
                            "user's tx.origin."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=snippet,
                        remediation=(
                            "Replace `tx.origin` with `msg.sender` for authorization:\n"
                            "```solidity\n"
                            "require(msg.sender == owner, 'Not authorized');\n"
                            "```"
                        ),
                    ))

        return findings


class UnprotectedWithdrawDetector(BaseDetector):
    """Detect withdrawal functions without access control."""

    DETECTOR_ID = "SCWE-049-001"
    NAME = "Unprotected Ether Withdrawal"
    DESCRIPTION = (
        "Detects functions that transfer ETH without proper access control, "
        "allowing anyone to drain the contract's balance."
    )
    SCWE_ID = "SCWE-049"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "access_control"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Find functions named withdraw* or that transfer ETH
        func_pattern = re.compile(
            r'function\s+(withdraw\w*|emergencyWithdraw\w*|drain\w*)\s*\([^)]*\)\s+'
            r'((?:public|external)[^{]*)\{',
            re.IGNORECASE,
        )

        for match in func_pattern.finditer(source):
            func_name = match.group(1)
            modifiers = match.group(2)

            # Check for access control
            has_access = any(
                mod in modifiers
                for mod in ["onlyOwner", "onlyAdmin", "onlyRole", "auth", "restricted"]
            )

            if not has_access:
                line_no = source[:match.start()].count("\n") + 1
                snippet = "\n".join(
                    lines[max(0, line_no - 1):min(len(lines), line_no + 5)]
                )
                findings.append(self._make_finding(
                    title=f"Unprotected withdrawal function `{func_name}`",
                    description=(
                        f"The function `{func_name}` can withdraw ETH but has no "
                        "access control. Anyone can call this function and drain "
                        "the contract's ETH balance."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no,
                    end_line=line_no + 4,
                    snippet=snippet,
                    remediation=(
                        "Add an access control modifier:\n"
                        "```solidity\n"
                        f"function {func_name}() external onlyOwner {{\n"
                        "    // withdrawal logic\n"
                        "}\n```"
                    ),
                ))

        return findings


class UnprotectedSelfDestructDetector(BaseDetector):
    """Detect selfdestruct without access control."""

    DETECTOR_ID = "SCWE-050-001"
    NAME = "Unprotected SELFDESTRUCT"
    DESCRIPTION = (
        "Detects use of selfdestruct without proper access control, which "
        "could allow anyone to destroy the contract and steal its ETH balance."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "access_control"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        for i, line in enumerate(lines):
            if "selfdestruct(" in line:
                # Check surrounding context for access control
                context_start = max(0, i - 10)
                context_lines = lines[context_start:i + 1]
                context_str = "\n".join(context_lines)

                has_protection = bool(re.search(
                    r'onlyOwner|require\s*\(\s*msg\.sender\s*==|onlyAdmin|'
                    r'onlyRole|_checkOwner|auth\b',
                    context_str,
                ))

                if not has_protection:
                    snippet = "\n".join(
                        lines[max(0, i - 2):min(len(lines), i + 2)]
                    )
                    findings.append(self._make_finding(
                        title="Unprotected selfdestruct",
                        description=(
                            "The selfdestruct instruction can be called without "
                            "access control. An attacker could destroy the contract "
                            "and redirect its entire ETH balance."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=snippet,
                        remediation=(
                            "Add access control or remove selfdestruct entirely. "
                            "Note: selfdestruct is deprecated since EIP-6049.\n"
                            "```solidity\n"
                            "function destroy() external onlyOwner {\n"
                            "    selfdestruct(payable(owner()));\n"
                            "}\n```"
                        ),
                    ))

        return findings

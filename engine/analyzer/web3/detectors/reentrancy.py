"""Reentrancy detectors — SCWE-046.

Reentrancy is one of the most critical smart contract vulnerabilities.
These detectors identify patterns where external calls are made before
state changes, allowing attackers to re-enter the contract.
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class ReentrancyETHDetector(BaseDetector):
    """Detect classic reentrancy via ETH transfers (call.value)."""

    DETECTOR_ID = "SCWE-046-001"
    NAME = "Reentrancy via ETH Transfer"
    DESCRIPTION = (
        "Detects functions that make external ETH transfers (call{value:}) "
        "before updating state variables. An attacker can re-enter the function "
        "via a fallback/receive function and drain funds."
    )
    SCWE_ID = "SCWE-046"
    CWE_ID = "CWE-841"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "reentrancy"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Pattern: .call{value: ...}(...) followed by state change
        call_pattern = re.compile(
            r'\.call\s*\{?\s*value\s*:', re.IGNORECASE
        )
        state_change_pattern = re.compile(
            r'(balances\[|_balances\[|balance\[|deposits\[|amounts\[)'
        )

        in_function = False
        function_start = 0
        function_name = ""
        call_line = -1
        call_found = False

        for i, line in enumerate(lines):
            # Track function boundaries
            func_match = re.match(r'\s*function\s+(\w+)', line)
            if func_match:
                # Check previous function
                if call_found and call_line > 0:
                    # Look for state changes after the call
                    pass
                in_function = True
                function_start = i
                function_name = func_match.group(1)
                call_line = -1
                call_found = False

            if call_pattern.search(line):
                call_found = True
                call_line = i

            # If we found a call, look for state changes after it
            if call_found and call_line >= 0 and i > call_line:
                if state_change_pattern.search(line):
                    snippet = "\n".join(
                        lines[max(0, call_line - 2):min(len(lines), i + 3)]
                    )
                    findings.append(self._make_finding(
                        title=f"Reentrancy vulnerability in `{function_name}`",
                        description=(
                            f"The function `{function_name}` makes an external ETH transfer "
                            f"(line {call_line + 1}) before updating state (line {i + 1}). "
                            "An attacker can exploit this by re-entering the function "
                            "from a malicious fallback/receive function before the state "
                            "is updated, potentially draining all funds."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=call_line + 1,
                        end_line=i + 1,
                        snippet=snippet,
                        remediation=(
                            "Apply the checks-effects-interactions pattern:\n"
                            "1. Perform all checks first\n"
                            "2. Update state variables\n"
                            "3. Make external calls last\n\n"
                            "Alternatively, use OpenZeppelin's ReentrancyGuard:\n"
                            "```solidity\nimport '@openzeppelin/contracts/security/ReentrancyGuard.sol';\n"
                            "function withdraw() external nonReentrant { ... }\n```"
                        ),
                    ))

        return findings


class ReentrancyCrossFunction(BaseDetector):
    """Detect cross-function reentrancy patterns."""

    DETECTOR_ID = "SCWE-046-002"
    NAME = "Cross-Function Reentrancy"
    DESCRIPTION = (
        "Detects cross-function reentrancy where an external call in one function "
        "allows re-entry to a different function that reads stale state."
    )
    SCWE_ID = "SCWE-046"
    CWE_ID = "CWE-841"
    SEVERITY = Severity.HIGH
    CATEGORY = "reentrancy"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Find functions with external calls but no ReentrancyGuard
        external_call_funcs: list[tuple[str, int]] = []
        has_reentrancy_guard = "nonReentrant" in source or "ReentrancyGuard" in source

        if has_reentrancy_guard:
            return findings  # Contract uses ReentrancyGuard

        for i, line in enumerate(lines):
            func_match = re.match(r'\s*function\s+(\w+)', line)
            if func_match:
                func_name = func_match.group(1)

            if re.search(r'\.call[({]|\.transfer\(|\.send\(', line):
                external_call_funcs.append((func_name, i))

        # If there are multiple public/external functions and external calls without guard
        public_funcs = len(re.findall(
            r'function\s+\w+\s*\([^)]*\)\s*(public|external)', source
        ))

        if len(external_call_funcs) > 0 and public_funcs > 1:
            for func_name, line_no in external_call_funcs:
                snippet = "\n".join(
                    lines[max(0, line_no - 2):min(len(lines), line_no + 3)]
                )
                findings.append(self._make_finding(
                    title=f"Potential cross-function reentrancy via `{func_name}`",
                    description=(
                        f"The function `{func_name}` makes an external call without "
                        "ReentrancyGuard protection. In a contract with multiple "
                        "public functions sharing state, an attacker could re-enter "
                        "a different function during the external call and read/modify "
                        "stale state."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    remediation=(
                        "Add OpenZeppelin's ReentrancyGuard to all functions that "
                        "interact with shared state:\n"
                        "```solidity\nimport '@openzeppelin/contracts/security/ReentrancyGuard.sol';\n"
                        "contract MyContract is ReentrancyGuard { ... }\n```"
                    ),
                ))

        return findings


class ReadOnlyReentrancy(BaseDetector):
    """Detect read-only reentrancy (view function reads stale state during reentry)."""

    DETECTOR_ID = "SCWE-046-003"
    NAME = "Read-Only Reentrancy"
    DESCRIPTION = (
        "Detects read-only reentrancy where a view function returns stale data "
        "during an external call, potentially misleading other contracts that "
        "depend on it."
    )
    SCWE_ID = "SCWE-046"
    CWE_ID = "CWE-841"
    SEVERITY = Severity.HIGH
    CATEGORY = "reentrancy"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Find view/pure functions that read state
        view_functions = re.findall(
            r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)\s+view',
            source,
        )

        # Find functions with external calls that modify the same state
        has_external_calls = bool(re.search(r'\.call[({]', source))

        if view_functions and has_external_calls:
            for view_func in view_functions:
                # Find the line of this view function
                for i, line in enumerate(lines):
                    if re.search(rf'function\s+{view_func}\s*\(', line):
                        snippet = "\n".join(
                            lines[max(0, i):min(len(lines), i + 5)]
                        )
                        findings.append(self._make_finding(
                            title=f"Potential read-only reentrancy via `{view_func}`",
                            description=(
                                f"The view function `{view_func}` may return stale data "
                                "if called during the execution of an external call in another "
                                "function. Other contracts relying on this view function's "
                                "return value could be manipulated."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i + 1,
                            end_line=i + 5,
                            snippet=snippet,
                            severity=Severity.MEDIUM,
                            remediation=(
                                "Ensure state is updated before any external calls, "
                                "or use a reentrancy lock that also protects view functions. "
                                "Consider using a `nonReentrantView` pattern."
                            ),
                        ))
                        break

        return findings

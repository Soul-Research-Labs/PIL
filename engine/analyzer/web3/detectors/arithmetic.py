"""Arithmetic and integer safety detectors — SCWE-047, SCWE-041, SCWE-080.

Detect integer overflow/underflow, unsafe downcasting, and incorrect type conversions.
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class UncheckedArithmeticDetector(BaseDetector):
    """Detect unchecked arithmetic blocks that may overflow/underflow."""

    DETECTOR_ID = "SCWE-047-001"
    NAME = "Unchecked Arithmetic"
    DESCRIPTION = (
        "Detects the use of `unchecked { }` blocks in Solidity >=0.8.0 where "
        "arithmetic operations may overflow or underflow without reverting."
    )
    SCWE_ID = "SCWE-047"
    CWE_ID = "CWE-190"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "arithmetic"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Find unchecked blocks
        pattern = re.compile(r'unchecked\s*\{')

        for match in pattern.finditer(source):
            line_no = source[:match.start()].count("\n") + 1

            # Extract the unchecked block content
            brace_count = 0
            block_start = match.start()
            block_end = match.start()
            started = False
            for j, char in enumerate(source[match.start():]):
                if char == "{":
                    brace_count += 1
                    started = True
                elif char == "}":
                    brace_count -= 1
                if started and brace_count == 0:
                    block_end = match.start() + j
                    break

            block_content = source[match.start():block_end + 1]

            # Check for risky operations inside unchecked blocks
            has_user_input = bool(re.search(
                r'(amount|value|balance|_amount|_value|msg\.value)', block_content
            ))
            has_arithmetic = bool(re.search(r'[\+\-\*\/]', block_content))

            if has_user_input and has_arithmetic:
                snippet = "\n".join(
                    lines[max(0, line_no - 1):min(len(lines), line_no + 5)]
                )
                findings.append(self._make_finding(
                    title="Unchecked arithmetic with user-controlled values",
                    description=(
                        "An `unchecked` block contains arithmetic operations on values "
                        "that may be user-controlled. In Solidity >=0.8.0, arithmetic "
                        "normally reverts on overflow/underflow, but `unchecked` blocks "
                        "disable this protection."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no,
                    end_line=line_no + block_content.count("\n"),
                    snippet=snippet,
                    remediation=(
                        "Validate inputs before performing unchecked arithmetic:\n"
                        "```solidity\n"
                        "require(a + b >= a, 'Overflow');\n"
                        "unchecked { result = a + b; }\n"
                        "```\n"
                        "Or remove the unchecked block if overflow protection is needed."
                    ),
                ))

        return findings


class UnsafeDowncastDetector(BaseDetector):
    """Detect unsafe integer downcasting."""

    DETECTOR_ID = "SCWE-041-001"
    NAME = "Unsafe Downcasting"
    DESCRIPTION = (
        "Detects implicit or explicit casting from larger integer types to smaller ones "
        "(e.g., uint256 to uint128) which can silently truncate values."
    )
    SCWE_ID = "SCWE-041"
    CWE_ID = "CWE-681"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "arithmetic"

    # Integer types ordered by size
    UINT_TYPES = ["uint8", "uint16", "uint32", "uint64", "uint128", "uint256"]
    INT_TYPES = ["int8", "int16", "int32", "int64", "int128", "int256"]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Pattern: typecast like uint128(someValue) or uint64(value)
        cast_pattern = re.compile(
            r'(uint8|uint16|uint32|uint64|uint128|int8|int16|int32|int64|int128)\s*\('
        )

        for i, line in enumerate(lines):
            for match in cast_pattern.finditer(line):
                target_type = match.group(1)
                snippet = "\n".join(
                    lines[max(0, i - 1):min(len(lines), i + 2)]
                )
                findings.append(self._make_finding(
                    title=f"Unsafe downcast to `{target_type}`",
                    description=(
                        f"A value is being cast to `{target_type}`, which may truncate "
                        "the value if it exceeds the target type's maximum. This could "
                        "lead to unexpected behavior or loss of funds."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=i + 1,
                    end_line=i + 1,
                    snippet=snippet,
                    severity=Severity.MEDIUM,
                    remediation=(
                        f"Use OpenZeppelin's SafeCast library:\n"
                        "```solidity\n"
                        "import '@openzeppelin/contracts/utils/math/SafeCast.sol';\n"
                        "using SafeCast for uint256;\n"
                        f"uint128 safeValue = someValue.to{target_type.capitalize()}();\n"
                        "```"
                    ),
                ))

        return findings


class DivisionBeforeMultiplication(BaseDetector):
    """Detect division before multiplication which causes precision loss."""

    DETECTOR_ID = "SCWE-047-002"
    NAME = "Division Before Multiplication"
    DESCRIPTION = (
        "Detects patterns where division is performed before multiplication, "
        "which causes precision loss in integer arithmetic since Solidity "
        "uses integer division (rounding towards zero)."
    )
    SCWE_ID = "SCWE-047"
    CWE_ID = "CWE-682"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "arithmetic"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Pattern: (a / b) * c or a / b * c
        pattern = re.compile(r'(\w+\s*/\s*\w+)\s*\*\s*\w+')

        for i, line in enumerate(lines):
            if pattern.search(line):
                snippet = "\n".join(
                    lines[max(0, i - 1):min(len(lines), i + 2)]
                )
                findings.append(self._make_finding(
                    title="Division before multiplication (precision loss)",
                    description=(
                        "Division is performed before multiplication. Since Solidity "
                        "uses integer division, intermediate results are rounded down, "
                        "causing precision loss. Multiply first, then divide."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=i + 1,
                    end_line=i + 1,
                    snippet=snippet,
                    severity=Severity.LOW,
                    remediation=(
                        "Rearrange to multiply before dividing:\n"
                        "```solidity\n"
                        "// Instead of: (a / b) * c\n"
                        "// Use:        (a * c) / b\n"
                        "```"
                    ),
                ))

        return findings

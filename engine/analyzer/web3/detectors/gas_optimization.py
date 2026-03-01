"""Gas optimization detectors — detect inefficient patterns and suggest savings."""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class StoragePackingDetector(BaseDetector):
    """Detect inefficient storage variable packing."""

    DETECTOR_ID = "GAS-001"
    NAME = "Inefficient Storage Packing"
    DESCRIPTION = (
        "Detects state variables that could be packed into fewer storage slots "
        "by reordering. Each storage slot is 32 bytes; smaller types that fit "
        "together in one slot save gas."
    )
    SCWE_ID = "SCWE-040"
    SEVERITY = Severity.GAS
    CATEGORY = "gas_optimization"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Track consecutive state variable declarations
        var_pattern = re.compile(
            r'^\s*(uint\d+|int\d+|bool|address|bytes\d+)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;'
        )

        variables: list[tuple[str, str, int]] = []  # (type, name, line)

        for i, line in enumerate(lines):
            match = var_pattern.match(line)
            if match:
                variables.append((match.group(1), match.group(2), i))

        # Check for suboptimal ordering
        type_sizes = {
            "bool": 1, "uint8": 1, "int8": 1, "bytes1": 1,
            "uint16": 2, "int16": 2, "bytes2": 2,
            "uint32": 4, "int32": 4, "bytes4": 4,
            "address": 20, "uint160": 20,
            "uint64": 8, "int64": 8, "bytes8": 8,
            "uint128": 16, "int128": 16, "bytes16": 16,
            "uint256": 32, "int256": 32, "bytes32": 32,
        }

        if len(variables) < 2:
            return findings

        # Check if small types are sandwiched between uint256s
        for j in range(1, len(variables) - 1):
            prev_type, _, prev_line = variables[j - 1]
            curr_type, curr_name, curr_line = variables[j]
            next_type, _, next_line = variables[j + 1]

            prev_size = type_sizes.get(prev_type, 32)
            curr_size = type_sizes.get(curr_type, 32)
            next_size = type_sizes.get(next_type, 32)

            if prev_size == 32 and curr_size < 32 and next_size == 32:
                snippet = "\n".join(
                    lines[max(0, prev_line):min(len(lines), next_line + 1)]
                )
                findings.append(self._make_finding(
                    title=f"Suboptimal storage packing: `{curr_name}`",
                    description=(
                        f"The variable `{curr_name}` ({curr_type}, {curr_size} bytes) "
                        f"is between two 32-byte variables, wasting a full storage slot. "
                        "Group smaller variables together to pack them into fewer slots."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=curr_line + 1,
                    end_line=curr_line + 1,
                    snippet=snippet,
                    remediation=(
                        "Move smaller variables next to each other:\n"
                        "```solidity\n"
                        "// Pack together: bool + address = 21 bytes (< 32, fits 1 slot)\n"
                        "bool public active;\n"
                        "address public owner;\n"
                        "// Then 32-byte vars\n"
                        "uint256 public amount;\n"
                        "```"
                    ),
                    metadata={"estimated_gas_saved": 20000},
                ))

        return findings


class CalldataVsMemoryDetector(BaseDetector):
    """Detect function params that should use calldata instead of memory."""

    DETECTOR_ID = "GAS-002"
    NAME = "Use calldata Instead of memory"
    DESCRIPTION = (
        "Detects external function parameters using `memory` that could use "
        "`calldata` instead, saving gas on copy operations."
    )
    SCWE_ID = ""
    SEVERITY = Severity.GAS
    CATEGORY = "gas_optimization"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Pattern: external function with memory array/string/bytes params
        pattern = re.compile(
            r'function\s+(\w+)\s*\(([^)]*\b(string|bytes|uint\d*\[\]|address\[\]|int\d*\[\])\s+memory\s+\w+[^)]*)\)\s*external'
        )

        for match in pattern.finditer(source):
            func_name = match.group(1)
            line_no = source[:match.start()].count("\n") + 1
            snippet = "\n".join(
                lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
            )
            findings.append(self._make_finding(
                title=f"Use `calldata` in `{func_name}`",
                description=(
                    f"The external function `{func_name}` uses `memory` for "
                    "reference-type parameters. Since the data is not modified, "
                    "using `calldata` avoids copying and saves gas."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no,
                end_line=line_no,
                snippet=snippet,
                remediation=(
                    "Replace `memory` with `calldata` for read-only parameters:\n"
                    "```solidity\n"
                    f"function {func_name}(string calldata data) external {{ ... }}\n"
                    "```"
                ),
                metadata={"estimated_gas_saved": 600},
            ))

        return findings


class CacheStorageVariableDetector(BaseDetector):
    """Detect storage variables read multiple times in loops."""

    DETECTOR_ID = "GAS-003"
    NAME = "Cache Storage Variable in Loop"
    DESCRIPTION = (
        "Detects storage variable reads inside loops, where caching the "
        "value in a local variable would save ~100 gas per SLOAD."
    )
    SCWE_ID = ""
    SEVERITY = Severity.GAS
    CATEGORY = "gas_optimization"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Find loops
        loop_pattern = re.compile(r'(for|while)\s*\(')
        storage_read_pattern = re.compile(r'\b(\w+)\.length\b')

        for i, line in enumerate(lines):
            if loop_pattern.search(line):
                # Check condition for .length reads
                match = storage_read_pattern.search(line)
                if match:
                    array_name = match.group(1)
                    snippet = "\n".join(
                        lines[max(0, i - 1):min(len(lines), i + 3)]
                    )
                    findings.append(self._make_finding(
                        title=f"Cache `{array_name}.length` outside loop",
                        description=(
                            f"Reading `{array_name}.length` from storage on every "
                            "loop iteration costs ~100 gas per SLOAD. Cache it in "
                            "a local variable before the loop."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=snippet,
                        remediation=(
                            "Cache the length:\n"
                            "```solidity\n"
                            f"uint256 len = {array_name}.length;\n"
                            "for (uint256 i = 0; i < len; i++) {{ ... }}\n"
                            "```"
                        ),
                        metadata={"estimated_gas_saved": 100},
                    ))

        return findings

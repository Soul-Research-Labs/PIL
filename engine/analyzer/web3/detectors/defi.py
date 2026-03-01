"""Oracle and DeFi detectors — SCWE-028, SCWE-037, SCWE-058, SCWE-077.

Detect price oracle manipulation, front-running, DoS via gas limit, and rate limiting issues.
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class PriceOracleManipulationDetector(BaseDetector):
    """Detect single-block price oracle usage vulnerable to flash loan attacks."""

    DETECTOR_ID = "SCWE-028-001"
    NAME = "Price Oracle Manipulation"
    DESCRIPTION = (
        "Detects contracts that read prices from AMM spot prices or single-block "
        "oracle snapshots, which are vulnerable to flash loan manipulation."
    )
    SCWE_ID = "SCWE-028"
    CWE_ID = "CWE-345"
    SEVERITY = Severity.HIGH
    CATEGORY = "oracle"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Spot price patterns (vulnerable to flash loans)
        spot_patterns = [
            (r'getReserves\(\)', "Uniswap getReserves() spot price"),
            (r'slot0\(\)', "Uniswap V3 slot0() spot price"),
            (r'getAmountOut\(', "AMM getAmountOut calculation"),
            (r'getAmountsOut\(', "AMM getAmountsOut calculation"),
            (r'balanceOf\(.*\)\s*/\s*totalSupply', "Balance ratio as price"),
        ]

        # TWAP / Safe oracle patterns (not vulnerable)
        safe_patterns = [
            "observe(", "consult(", "TWAP", "twap",
            "getTimeWeightedAverage", "OracleLibrary",
        ]

        has_safe_oracle = any(p in source for p in safe_patterns)

        for pattern, desc in spot_patterns:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n") + 1
                snippet = "\n".join(
                    lines[max(0, line_no - 2):min(len(lines), line_no + 2)]
                )
                severity = Severity.MEDIUM if has_safe_oracle else Severity.HIGH
                findings.append(self._make_finding(
                    title=f"Price oracle manipulation via {desc}",
                    description=(
                        f"The contract uses {desc} which returns the current spot price. "
                        "This is vulnerable to flash loan attacks where an attacker can "
                        "temporarily manipulate the price in a single transaction."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no,
                    end_line=line_no,
                    snippet=snippet,
                    severity=severity,
                    remediation=(
                        "Use a time-weighted average price (TWAP) oracle:\n"
                        "```solidity\n"
                        "// Uniswap V3 TWAP\n"
                        "import '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';\n"
                        "(int24 tick, ) = OracleLibrary.consult(pool, twapInterval);\n"
                        "```\n"
                        "Or use Chainlink price feeds for reliable pricing."
                    ),
                ))

        return findings


class FrontRunningDetector(BaseDetector):
    """Detect functions vulnerable to front-running / MEV attacks."""

    DETECTOR_ID = "SCWE-037-001"
    NAME = "Front-Running Vulnerability"
    DESCRIPTION = (
        "Detects functions that are vulnerable to front-running where miners "
        "or MEV searchers can observe pending transactions and profit by "
        "reordering or inserting their own transactions."
    )
    SCWE_ID = "SCWE-037"
    CWE_ID = "CWE-362"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "defi"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Patterns vulnerable to front-running
        vulnerable_patterns = [
            (r'approve\s*\(', "ERC-20 approve (race condition)"),
            (r'swap\w*\(.*\n?.*(?:amountOutMin|minReturn)\s*[=:]\s*0', "Swap with zero slippage"),
            (r'deadline\s*[=:]\s*block\.timestamp', "Deadline set to block.timestamp (useless)"),
        ]

        # Commit-reveal pattern (protection)
        has_commit_reveal = bool(re.search(
            r'commit|reveal|hash.*secret|sealed', source, re.IGNORECASE
        ))

        if has_commit_reveal:
            return findings

        for pattern, desc in vulnerable_patterns:
            for match in re.finditer(pattern, source, re.MULTILINE):
                line_no = source[:match.start()].count("\n") + 1
                snippet = "\n".join(
                    lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
                )
                findings.append(self._make_finding(
                    title=f"Front-running: {desc}",
                    description=(
                        f"Detected potential front-running vulnerability: {desc}. "
                        "Miners or MEV searchers can observe this transaction in the "
                        "mempool and profit by reordering transactions."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no,
                    end_line=line_no,
                    snippet=snippet,
                    remediation=(
                        "Implement protection against front-running:\n"
                        "1. Use commit-reveal schemes\n"
                        "2. Set reasonable slippage limits\n"
                        "3. Use private mempools (Flashbots)\n"
                        "4. Set meaningful deadlines"
                    ),
                ))

        return findings


class UnboundedLoopDetector(BaseDetector):
    """Detect unbounded loops that could exceed gas limit."""

    DETECTOR_ID = "SCWE-058-001"
    NAME = "DoS via Unbounded Loop"
    DESCRIPTION = (
        "Detects loops that iterate over dynamic-length arrays or mappings "
        "without bounds, which could exceed the block gas limit and cause DoS."
    )
    SCWE_ID = "SCWE-058"
    CWE_ID = "CWE-400"
    SEVERITY = Severity.HIGH
    CATEGORY = "defi"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Patterns: loops using .length of a storage array
        patterns = [
            re.compile(r'for\s*\(\s*\w+\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\.length\s*;'),
            re.compile(r'for\s*\(\s*\w+\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*;'),
        ]

        for i, line in enumerate(lines):
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    array_name = match.group(1)
                    # Check if the array could grow unboundedly
                    is_push_used = bool(re.search(
                        rf'{array_name}\.push\(', source
                    ))
                    if is_push_used:
                        snippet = "\n".join(
                            lines[max(0, i - 1):min(len(lines), i + 3)]
                        )
                        findings.append(self._make_finding(
                            title=f"Unbounded loop over `{array_name}`",
                            description=(
                                f"A loop iterates over `{array_name}` which can grow "
                                "without bounds via push(). If the array grows large enough, "
                                "the loop will exceed the block gas limit, permanently "
                                "bricking the function (DoS)."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=snippet,
                            remediation=(
                                "Implement pagination or batch processing:\n"
                                "```solidity\n"
                                "function process(uint start, uint batchSize) external {\n"
                                "    uint end = min(start + batchSize, array.length);\n"
                                "    for (uint i = start; i < end; i++) { ... }\n"
                                "}\n```\n"
                                "Or use a pull pattern instead of iterating."
                            ),
                        ))

        return findings


class WeakRandomnessDetector(BaseDetector):
    """Detect use of predictable randomness sources."""

    DETECTOR_ID = "SCWE-024-001"
    NAME = "Weak Randomness Source"
    DESCRIPTION = (
        "Detects the use of block variables (block.timestamp, blockhash, "
        "block.difficulty/prevrandao) as randomness sources, which are "
        "predictable and can be manipulated by miners."
    )
    SCWE_ID = "SCWE-024"
    CWE_ID = "CWE-330"
    SEVERITY = Severity.HIGH
    CATEGORY = "cryptography"

    WEAK_SOURCES = [
        ("block.timestamp", "block timestamp"),
        ("block.difficulty", "block difficulty"),
        ("block.prevrandao", "block prevrandao"),
        ("blockhash(", "blockhash"),
        ("block.number", "block number"),
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Check if Chainlink VRF is used (safe)
        if "VRFConsumerBase" in source or "VRFCoordinatorV2" in source:
            return findings

        for weak_source, name in self.WEAK_SOURCES:
            for i, line in enumerate(lines):
                if weak_source in line:
                    # Check if used in randomness/hashing context
                    context_str = "\n".join(lines[max(0, i - 2):min(len(lines), i + 3)])
                    is_random_context = bool(re.search(
                        r'keccak256|random|rand|lottery|winner|shuffle|select',
                        context_str, re.IGNORECASE,
                    ))
                    if is_random_context:
                        snippet = "\n".join(
                            lines[max(0, i - 1):min(len(lines), i + 2)]
                        )
                        findings.append(self._make_finding(
                            title=f"Weak randomness via {name}",
                            description=(
                                f"The contract uses `{weak_source}` as a randomness source. "
                                "Block variables are predictable and can be manipulated by "
                                "miners/validators. This makes the randomness exploitable."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=snippet,
                            remediation=(
                                "Use Chainlink VRF for verifiable randomness:\n"
                                "```solidity\n"
                                "import '@chainlink/contracts/src/v0.8/vrf/VRFConsumerBaseV2.sol';\n"
                                "```\n"
                                "Or implement a commit-reveal scheme for on-chain randomness."
                            ),
                        ))

        return findings

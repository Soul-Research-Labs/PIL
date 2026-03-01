"""MEV and sandwich attack detectors — SCWE-041.

Detect surfaces vulnerable to Maximal Extractable Value (MEV) attacks:
  - Sandwich attack targets (large swaps without slippage protection)
  - Liquidation MEV opportunities
  - JIT liquidity detection
  - Backrunning / frontrunning surfaces
  - Missing commit-reveal patterns
  - Block-dependent logic that miners can influence
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class SandwichAttackDetector(BaseDetector):
    """Detect functions vulnerable to sandwich attacks."""

    DETECTOR_ID = "SCWE-041-001"
    NAME = "Sandwich Attack Surface"
    DESCRIPTION = (
        "Detects swap operations with insufficient or zero slippage protection, "
        "creating profitable sandwich attack opportunities for MEV searchers."
    )
    SCWE_ID = "SCWE-041"
    CWE_ID = "CWE-362"
    SEVERITY = Severity.HIGH
    CATEGORY = "mev"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # 1. Zero slippage on swaps
        zero_slippage_patterns = [
            (r'amountOutMin(?:imum)?\s*[=:]\s*0', "amountOutMinimum set to 0"),
            (r'minAmountOut\s*[=:]\s*0', "minAmountOut set to 0"),
            (r'sqrtPriceLimitX96\s*[=:]\s*0', "sqrtPriceLimitX96 set to 0"),
            (r'slippage\s*[=:]\s*0', "slippage set to 0"),
        ]

        for pattern, desc in zero_slippage_patterns:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(
                    lines[max(0, line_no - 2):min(len(lines), line_no + 3)]
                )
                findings.append(self._make_finding(
                    title=f"Sandwich attack: {desc}",
                    description=(
                        f"The swap at line {line_no + 1} has {desc}. "
                        "An MEV bot can:\n"
                        "1. Front-run this transaction by buying the output token\n"
                        "2. Let this swap execute at a worse price\n"
                        "3. Back-run by selling, extracting value from the user"
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    remediation=(
                        "Set a meaningful minimum output amount:\n"
                        "```solidity\n"
                        "// Calculate with acceptable slippage (e.g., 0.5%)\n"
                        "uint256 minOut = expectedAmount * 995 / 1000;\n"
                        "router.exactInputSingle(ExactInputSingleParams({\n"
                        "    ...,\n"
                        "    amountOutMinimum: minOut,\n"
                        "    sqrtPriceLimitX96: 0 // or set a price limit\n"
                        "}));\n```"
                    ),
                ))

        # 2. Deadline set to block.timestamp (useless)
        for match in re.finditer(
            r'deadline\s*[=:]\s*block\.timestamp',
            source,
        ):
            line_no = source[:match.start()].count("\n")
            snippet = "\n".join(
                lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
            )
            findings.append(self._make_finding(
                title="Useless deadline: block.timestamp",
                description=(
                    f"Deadline is set to block.timestamp (line {line_no + 1}), "
                    "which always passes validation. The transaction can be held "
                    "by miners/MEV searchers indefinitely and executed when "
                    "profitable for them."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no + 1,
                end_line=line_no + 1,
                snippet=snippet,
                severity=Severity.MEDIUM,
                remediation=(
                    "Set a meaningful deadline:\n"
                    "```solidity\n"
                    "uint256 deadline = block.timestamp + 300; // 5 minutes\n"
                    "```\n"
                    "Or accept deadline as a parameter from the user."
                ),
            ))

        # 3. Large token approvals without time limits
        for match in re.finditer(
            r'approve\s*\([^,]+,\s*type\s*\(\s*uint256\s*\)\s*\.max\s*\)',
            source,
        ):
            line_no = source[:match.start()].count("\n")
            snippet = "\n".join(
                lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
            )
            findings.append(self._make_finding(
                title="Unlimited approval — MEV drain risk",
                description=(
                    f"Unlimited token approval at line {line_no + 1}. If the "
                    "approved contract is exploited, all approved tokens can be "
                    "drained. MEV bots monitor for such vulnerabilities."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no + 1,
                end_line=line_no + 1,
                snippet=snippet,
                severity=Severity.LOW,
                remediation=(
                    "Approve only the needed amount per transaction:\n"
                    "```solidity\n"
                    "token.approve(spender, amount); // exact amount needed\n"
                    "// Reset approval after use\n"
                    "token.approve(spender, 0);\n```"
                ),
            ))

        return findings


class LiquidationMEVDetector(BaseDetector):
    """Detect liquidation mechanisms vulnerable to MEV."""

    DETECTOR_ID = "SCWE-041-002"
    NAME = "Liquidation MEV Opportunity"
    DESCRIPTION = (
        "Detects lending/borrowing contract liquidation functions that can be "
        "front-run by MEV searchers for profit, or that lack proper incentive "
        "alignment."
    )
    SCWE_ID = "SCWE-041"
    CWE_ID = "CWE-362"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "mev"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Detect liquidation functions
        for match in re.finditer(
            r'function\s+(liquidate\w*|liquidatePosition|liquidateUser|executeLiquidation)\s*\(',
            source,
        ):
            func_name = match.group(1)
            line_no = source[:match.start()].count("\n")
            func_end = min(len(lines), line_no + 30)
            func_text = "\n".join(lines[line_no:func_end])

            issues: list[str] = []

            # No close factor (can liquidate 100%)
            has_close_factor = bool(re.search(
                r'closeFactor|maxLiquidation|MAX_LIQUIDATION',
                func_text,
            ))
            if not has_close_factor:
                issues.append("No close factor — full position can be liquidated in one tx")

            # Fixed liquidation bonus
            if re.search(r'liquidationBonus\s*=\s*\d+', func_text):
                issues.append("Fixed liquidation bonus — may over/under-incentivize")

            # No dutch auction for bonus
            has_dutch_auction = bool(re.search(
                r'dutch|auction|decreasingBonus|timeWeighted',
                func_text, re.IGNORECASE,
            ))
            if not has_dutch_auction:
                issues.append("No dutch auction — all profit goes to fastest bot")

            if issues:
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 8)])
                findings.append(self._make_finding(
                    title=f"Liquidation MEV in `{func_name}()`",
                    description=(
                        f"The liquidation function `{func_name}` (line {line_no + 1}) "
                        "has MEV-related issues:\n" +
                        "\n".join(f"  - {i}" for i in issues) +
                        "\n\nMEV searchers will front-run liquidation opportunities, "
                        "extracting value from the protocol and borrowers."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 8,
                    snippet=snippet,
                    remediation=(
                        "Implement MEV-resistant liquidation:\n"
                        "1. Use a dutch auction to decrease liquidation bonus over time\n"
                        "2. Set a close factor (e.g., max 50% per liquidation)\n"
                        "3. Consider batch liquidation with priority queue\n"
                        "4. Use a private mempool or commit-reveal for liquidators"
                    ),
                ))

        return findings


class BlockDependenceDetector(BaseDetector):
    """Detect reliance on block properties for critical logic."""

    DETECTOR_ID = "SCWE-041-003"
    NAME = "Block-Dependent Critical Logic"
    DESCRIPTION = (
        "Detects use of block.timestamp, block.number, or blockhash for "
        "time-sensitive or random operations that miners can manipulate."
    )
    SCWE_ID = "SCWE-041"
    CWE_ID = "CWE-330"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "mev"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # block.timestamp in comparisons (not just deadline checks)
        for match in re.finditer(
            r'block\.timestamp\s*[<>=!]+\s*\w+|'
            r'\w+\s*[<>=!]+\s*block\.timestamp',
            source,
        ):
            line_no = source[:match.start()].count("\n")
            line_text = lines[line_no].strip()

            # Skip common safe patterns
            if any(skip in line_text.lower() for skip in [
                "deadline", "expir", "timeout", "lock"
            ]):
                continue

            snippet = "\n".join(
                lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
            )
            findings.append(self._make_finding(
                title="block.timestamp in critical logic",
                description=(
                    f"block.timestamp is used in a comparison at line {line_no + 1}. "
                    "Miners can manipulate block.timestamp by up to ~15 seconds, which "
                    "can affect time-dependent logic like auctions, vesting, or "
                    "interest calculations."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no + 1,
                end_line=line_no + 1,
                snippet=snippet,
                severity=Severity.LOW,
                remediation=(
                    "For critical timing logic:\n"
                    "1. Use block.number instead of block.timestamp when possible\n"
                    "2. Allow tolerance for timestamp manipulation\n"
                    "3. For randomness, use Chainlink VRF instead of blockhash"
                ),
            ))

        # blockhash for randomness
        for match in re.finditer(r'blockhash\s*\(', source):
            line_no = source[:match.start()].count("\n")
            snippet = "\n".join(
                lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
            )
            findings.append(self._make_finding(
                title="Weak randomness via blockhash",
                description=(
                    f"blockhash is used at line {line_no + 1}, likely for random "
                    "number generation. Miners can withhold blocks to influence "
                    "the result. Post-merge, validators know all block data beforehand."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no + 1,
                end_line=line_no + 1,
                snippet=snippet,
                severity=Severity.HIGH,
                remediation=(
                    "Use Chainlink VRF for verifiable randomness:\n"
                    "```solidity\n"
                    "import '@chainlink/contracts/src/v0.8/vrf/VRFConsumerBaseV2.sol';\n"
                    "// Request random number from VRF\n"
                    "uint256 requestId = COORDINATOR.requestRandomWords(...);\n"
                    "```"
                ),
            ))

        return findings


class ReturnBombDetector(BaseDetector):
    """Detect return bomb / returndata gas griefing."""

    DETECTOR_ID = "SCWE-041-004"
    NAME = "Return Bomb DoS"
    DESCRIPTION = (
        "Detects low-level calls that copy returned data without size limits, "
        "allowing a malicious callee to return huge data and grief the caller "
        "with excessive memory expansion gas costs."
    )
    SCWE_ID = "SCWE-041"
    CWE_ID = "CWE-400"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "mev"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # .call that copies all return data
        for match in re.finditer(
            r'\(bool\s+\w+\s*,\s*bytes\s+memory\s+\w+\)\s*=\s*\w+\.call',
            source,
        ):
            line_no = source[:match.start()].count("\n")

            # Check if return data is used (if not used, compiler may optimize)
            return_var = re.search(
                r'bytes\s+memory\s+(\w+)', match.group()
            )
            if return_var:
                var_name = return_var.group(1)
                # Check if return data variable is used later
                rest_of_func = "\n".join(lines[line_no + 1:min(len(lines), line_no + 20)])
                if var_name not in rest_of_func:
                    snippet = "\n".join(
                        lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
                    )
                    findings.append(self._make_finding(
                        title="Return bomb: unused return data copied",
                        description=(
                            f"The low-level call at line {line_no + 1} copies all return "
                            f"data into memory variable `{var_name}` but never uses it. "
                            "A malicious callee can return megabytes of data, causing "
                            "the caller to pay for memory expansion (gas griefing)."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + 1,
                        snippet=snippet,
                        remediation=(
                            "If return data is not needed, don't copy it:\n"
                            "```solidity\n"
                            "(bool success, ) = target.call{value: amount}(\"\");\n"
                            "require(success);\n"
                            "```\n"
                            "Or limit return data size using assembly:\n"
                            "```solidity\n"
                            "assembly {\n"
                            "    success := call(gas(), target, amount, 0, 0, 0, 0)\n"
                            "}\n```"
                        ),
                    ))

        return findings

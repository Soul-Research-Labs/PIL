"""Soul Protocol economic and DeFi vulnerability detectors.

Detects:
  - Flash loan attack vectors
  - Fee manipulation / dust attacks
  - Token inflation / minting abuse
  - Oracle manipulation in privacy context
  - MEV extraction from Soul operations
  - Griefing attacks on the protocol
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class FlashLoanGuardBypassDetector(BaseDetector):
    """Detect FlashLoanGuard bypass patterns."""

    DETECTOR_ID = "SOUL-ECON-001"
    NAME = "Soul Flash Loan Guard Bypass"
    DESCRIPTION = "Detects patterns that bypass Soul Protocol's FlashLoanGuard"
    SCWE_ID = "SOUL-070"
    CWE_ID = "CWE-863"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-economic"
    CONFIDENCE = 0.80

    _STATE_CHANGE = re.compile(
        r"function\s+\w*(deposit|withdraw|swap|transfer|bridge|relay|unlock)\w*\s*\(.*\)\s*(external|public)",
        re.IGNORECASE,
    )
    _FLASH_GUARD = re.compile(
        r"(flashLoanGuard|noFlashLoan|_checkFlashLoan|FlashLoanGuard|sameBlock)",
        re.IGNORECASE,
    )
    _BLOCK_CHECK = re.compile(
        r"(block\.number|blockNumber|lastBlock|_blockNumber)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        soul_indicators = [
            "Soul", "ShieldedPool", "PrivacyRouter", "NullifierRegistry",
            "CrossChainProofHub", "AtomicSwap", "StealthAddress",
        ]
        is_soul = any(ind in context.source_code for ind in soul_indicators)
        if not is_soul:
            return findings

        has_global_guard = bool(self._FLASH_GUARD.search(context.source_code))

        for i, line in enumerate(lines):
            if self._STATE_CHANGE.search(line):
                body = "\n".join(lines[i:min(i + 20, len(lines))])

                if not self._FLASH_GUARD.search(body) and not has_global_guard:
                    findings.append(self._make_finding(
                        title="State-changing function lacks flash loan protection",
                        description=(
                            f"Function at line {i + 1} performs a state change "
                            f"(deposit/withdraw/swap/bridge) without FlashLoanGuard "
                            f"protection. An attacker could use a flash loan to "
                            f"temporarily acquire large capital and exploit the "
                            f"function in a single transaction."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Apply FlashLoanGuard: "
                            "`modifier noFlashLoan() { "
                            "require(lastInteractionBlock[msg.sender] < block.number); "
                            "lastInteractionBlock[msg.sender] = block.number; _; }`"
                        ),
                    ))

        return findings


class DustAttackDetector(BaseDetector):
    """Detect dust amount attack vectors."""

    DETECTOR_ID = "SOUL-ECON-002"
    NAME = "Soul Dust Attack"
    DESCRIPTION = "Detects functions vulnerable to dust amount attacks"
    SCWE_ID = "SOUL-071"
    CWE_ID = "CWE-400"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "soul-economic"
    CONFIDENCE = 0.65

    _AMOUNT_PARAM = re.compile(r"uint256\s+(amount|value|deposit)", re.IGNORECASE)
    _MIN_CHECK = re.compile(r"(minAmount|MIN_AMOUNT|minDeposit|require.*amount\s*>=?\s*\d)", re.IGNORECASE)
    _ZERO_CHECK = re.compile(r"(require.*amount\s*>\s*0|amount\s*!=\s*0|amount\s*==\s*0)", re.IGNORECASE)
    _SHIELDED = re.compile(r"(deposit|shield|shieldedPool)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if "function" in line and self._AMOUNT_PARAM.search(line) and \
               self._SHIELDED.search(line):
                body = "\n".join(lines[i:min(i + 20, len(lines))])

                if not self._MIN_CHECK.search(body) and not self._ZERO_CHECK.search(body):
                    findings.append(self._make_finding(
                        title="Shielded pool function lacks minimum amount",
                        description=(
                            f"Function at line {i + 1} accepts an amount parameter "
                            f"without enforcing a minimum. In Soul's shielded pool, "
                            f"dust deposits (e.g., 1 wei) pollute the Merkle tree "
                            f"with useless commitments, increasing gas costs for "
                            f"legitimate users and bloating the anonymity set with "
                            f"identifiable tiny deposits."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Enforce minimum amount: "
                            "`require(amount >= MIN_DEPOSIT_AMOUNT, "
                            "\"Below minimum deposit\");`"
                        ),
                    ))

        return findings


class FeeManipulationDetector(BaseDetector):
    """Detect fee manipulation vulnerabilities."""

    DETECTOR_ID = "SOUL-ECON-003"
    NAME = "Soul Fee Manipulation"
    DESCRIPTION = "Detects fee calculation patterns vulnerable to manipulation"
    SCWE_ID = "SOUL-072"
    CWE_ID = "CWE-682"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-economic"
    CONFIDENCE = 0.70

    _FEE_CALC = re.compile(r"(fee|relayerFee|protocolFee|bridgeFee|gasFee)", re.IGNORECASE)
    _FEE_SET = re.compile(r"function\s+\w*(setFee|updateFee|changeFee)\w*\s*\(", re.IGNORECASE)
    _FEE_CAP = re.compile(r"(MAX_FEE|maxFee|feeCap|require.*fee\s*<=)", re.IGNORECASE)
    _FEE_FLOOR = re.compile(r"(MIN_FEE|minFee|feeFloor|require.*fee\s*>=)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._FEE_SET.search(line):
                body = "\n".join(lines[i:min(i + 15, len(lines))])

                if not self._FEE_CAP.search(body):
                    findings.append(self._make_finding(
                        title="Fee setter lacks maximum cap",
                        description=(
                            f"Fee setter at line {i + 1} has no upper bound. "
                            f"A compromised admin could set fees to 100%, "
                            f"effectively stealing all user funds in transit. "
                            f"Soul Protocol relay and bridge fees must be capped."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Cap fees: `require(newFee <= MAX_FEE, \"Fee too high\"); "
                            "// MAX_FEE = 500 (5%)`"
                        ),
                    ))

        # Check for fee-on-transfer issues in Soul context
        if any(kw in context.source_code for kw in [
            "transferFrom", "safeTransferFrom"
        ]) and self._FEE_CALC.search(context.source_code):
            for i, line in enumerate(lines):
                if "transferFrom" in line and not re.search(
                    r"(balanceBefore|balanceAfter|actualAmount)", context.source_code
                ):
                    fee_context = "\n".join(
                        lines[max(0, i - 5):min(i + 10, len(lines))]
                    )
                    if self._FEE_CALC.search(fee_context):
                        findings.append(self._make_finding(
                            title="Fee calculation doesn't account for transfer tax",
                            description=(
                                f"TransferFrom at line {i + 1} is used in a fee "
                                f"context without checking balanceBefore/After. "
                                f"Fee-on-transfer tokens would silently reduce "
                                f"the received amount, breaking fee calculations."
                            ),
                            file_path=context.contract_name + ".sol",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                            severity=Severity.MEDIUM,
                            remediation=(
                                "Measure actual transfer: "
                                "`uint256 before = token.balanceOf(address(this)); "
                                "token.transferFrom(from, address(this), amount); "
                                "uint256 actual = token.balanceOf(address(this)) - before;`"
                            ),
                        ))

        return findings


class MEVExtractionDetector(BaseDetector):
    """Detect MEV extraction vectors in Soul operations."""

    DETECTOR_ID = "SOUL-ECON-004"
    NAME = "Soul MEV Extraction"
    DESCRIPTION = "Detects MEV extraction vectors in Soul Protocol operations"
    SCWE_ID = "SOUL-073"
    CWE_ID = "CWE-362"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-economic"
    CONFIDENCE = 0.65

    _PRICE_DEPENDENT = re.compile(
        r"(getPrice|latestAnswer|priceOracle|exchange_rate|getAmountOut)",
        re.IGNORECASE,
    )
    _COMMIT_REVEAL = re.compile(
        r"(commit|reveal|sealed|commitHash|revealPhase)",
        re.IGNORECASE,
    )
    _MEV_PROTECT = re.compile(
        r"(MEVProtection|mevGuard|flashbots|privateTx|commitReveal|submarine)",
        re.IGNORECASE,
    )
    _SWAP_OP = re.compile(
        r"function\s+\w*(swap|exchange|convert|trade)\w*\s*\(",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._SWAP_OP.search(line):
                body = "\n".join(lines[i:min(i + 25, len(lines))])

                if self._PRICE_DEPENDENT.search(body) and \
                   not self._MEV_PROTECT.search(body):
                    findings.append(self._make_finding(
                        title="Swap vulnerable to sandwich attack",
                        description=(
                            f"Swap function at line {i + 1} uses a price oracle "
                            f"without MEV protection. A searcher could sandwich "
                            f"the transaction: front-run with a price-moving trade, "
                            f"let this tx execute at a worse price, then back-run. "
                            f"Soul Protocol includes MEVProtection module for this."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        remediation=(
                            "Integrate Soul MEVProtection: "
                            "`modifier mevProtected() { "
                            "require(mevProtection.isSafeContext()); _; }` "
                            "or use commit-reveal pattern."
                        ),
                    ))

        return findings


class GriefingAttackDetector(BaseDetector):
    """Detect griefing attack vectors in Soul Protocol."""

    DETECTOR_ID = "SOUL-ECON-005"
    NAME = "Soul Griefing Attack"
    DESCRIPTION = "Detects griefing attack vectors that disrupt Soul Protocol operations"
    SCWE_ID = "SOUL-074"
    CWE_ID = "CWE-400"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "soul-economic"
    CONFIDENCE = 0.65

    _LOOP = re.compile(r"for\s*\(.*;\s*\w+\s*<\s*\w+", re.IGNORECASE)
    _USER_LENGTH = re.compile(
        r"(\.length|\.size|numItems|count)\s*;?\s*$",
        re.IGNORECASE,
    )
    _GAS_LIMIT = re.compile(
        r"(gasLimit|MAX_BATCH|maxItems|MAX_ITERATIONS|require.*\.length\s*<=)",
        re.IGNORECASE,
    )
    _REVERT_ON_FAIL = re.compile(
        r"(require\(|revert\s|assert\()",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._LOOP.search(line):
                body = "\n".join(lines[max(0, i - 5):min(i + 15, len(lines))])

                if self._USER_LENGTH.search(body) and \
                   not self._GAS_LIMIT.search(body):
                    findings.append(self._make_finding(
                        title="Unbounded loop with user-controlled length",
                        description=(
                            f"Loop at line {i + 1} iterates over a user-controlled "
                            f"array without a maximum bound. An attacker could "
                            f"grow the array to cause out-of-gas reverts, griefing "
                            f"legitimate operations. In Soul Protocol, this could "
                            f"block batch nullifier processing or relay execution."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                        remediation=(
                            "Bound the loop: "
                            "`require(items.length <= MAX_BATCH_SIZE, \"Batch too large\");` "
                            "or use pagination."
                        ),
                    ))

        # Check for griefing via forced reverts in batches
        batch_funcs = re.finditer(
            r"function\s+\w*batch\w*\s*\(", context.source_code, re.IGNORECASE
        )
        for match in batch_funcs:
            pos = match.start()
            line_num = context.source_code[:pos].count("\n")
            body = "\n".join(lines[line_num:min(line_num + 30, len(lines))])

            has_try_catch = "try" in body and "catch" in body
            if not has_try_catch and self._REVERT_ON_FAIL.search(body):
                findings.append(self._make_finding(
                    title="Batch function reverts on single item failure",
                    description=(
                        f"Batch function near line {line_num + 1} reverts if any "
                        f"single item in the batch fails. An attacker could "
                        f"include a deliberately failing item to block the entire "
                        f"batch. In Soul Protocol batch nullifier operations, "
                        f"this would grief all other users in the batch."
                    ),
                    file_path=context.contract_name + ".sol",
                    start_line=line_num + 1,
                    end_line=line_num + 3,
                    snippet=lines[line_num].strip() if line_num < len(lines) else "",
                    remediation=(
                        "Use try-catch for individual items: "
                        "`try this.processSingle(items[i]) {} catch { "
                        "failedItems.push(i); continue; }`"
                    ),
                ))

        return findings

"""Flash loan attack detectors — SCWE-038.

Detect patterns vulnerable to flash-loan-powered exploits:
  - ERC-3156 callback manipulation
  - Aave/dYdX flash loan callbacks without validation
  - Single-transaction price manipulation surfaces
  - Flash mint abuse in ERC-20 wrappers
  - Balance-dependent access control bypassable via flash loans
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class FlashLoanCallbackDetector(BaseDetector):
    """Detect unprotected or exploitable flash loan callbacks."""

    DETECTOR_ID = "SCWE-038-001"
    NAME = "Unprotected Flash Loan Callback"
    DESCRIPTION = (
        "Detects flash loan callback functions (onFlashLoan, executeOperation, "
        "callFunction) that lack proper validation of the initiator, sender, "
        "or loan parameters, allowing attackers to trigger the callback maliciously."
    )
    SCWE_ID = "SCWE-038"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "flash_loan"

    # Known flash loan callback signatures
    CALLBACKS = [
        (r'function\s+onFlashLoan\s*\(', "ERC-3156 onFlashLoan"),
        (r'function\s+executeOperation\s*\(', "Aave executeOperation"),
        (r'function\s+callFunction\s*\(', "dYdX callFunction"),
        (r'function\s+uniswapV2Call\s*\(', "Uniswap V2 flash swap callback"),
        (r'function\s+uniswapV3FlashCallback\s*\(', "Uniswap V3 flash callback"),
        (r'function\s+uniswapV3SwapCallback\s*\(', "Uniswap V3 swap callback"),
        (r'function\s+pancakeCall\s*\(', "PancakeSwap flash callback"),
        (r'function\s+onFlashSwap\s*\(', "Generic flash swap callback"),
    ]

    # Validation patterns
    VALIDATIONS = [
        r'require\s*\(\s*msg\.sender\s*==',
        r'require\s*\(\s*initiator\s*==',
        r'require\s*\(\s*_initiator\s*==',
        r'if\s*\(\s*msg\.sender\s*!=',
        r'onlyPool',
        r'onlyLendingPool',
        r'onlyFlashLoanProvider',
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        for pattern, name in self.CALLBACKS:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n")
                # Extract function body (approximate with brace counting)
                func_body = self._extract_function_body(lines, line_no)
                func_text = "\n".join(func_body)

                has_validation = any(
                    re.search(v, func_text) for v in self.VALIDATIONS
                )

                if not has_validation:
                    snippet = "\n".join(lines[line_no:min(len(lines), line_no + 8)])
                    findings.append(self._make_finding(
                        title=f"Unprotected {name} callback",
                        description=(
                            f"The {name} callback at line {line_no + 1} lacks validation "
                            "of msg.sender or initiator. An attacker can call this function "
                            "directly or via a malicious flash loan provider to manipulate "
                            "the contract's state or drain funds."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + len(func_body),
                        snippet=snippet,
                        remediation=(
                            "Validate the callback caller and initiator:\n"
                            "```solidity\n"
                            "function onFlashLoan(\n"
                            "    address initiator, address token, uint256 amount,\n"
                            "    uint256 fee, bytes calldata data\n"
                            ") external override returns (bytes32) {\n"
                            "    require(msg.sender == address(lendingPool), \"Invalid caller\");\n"
                            "    require(initiator == address(this), \"Invalid initiator\");\n"
                            "    // ... logic ...\n"
                            "    return keccak256(\"ERC3156FlashBorrower.onFlashLoan\");\n"
                            "}\n```"
                        ),
                    ))

        return findings

    def _extract_function_body(
        self, lines: list[str], start: int, max_lines: int = 80
    ) -> list[str]:
        """Extract lines from function start to its closing brace."""
        depth = 0
        body: list[str] = []
        started = False
        for i in range(start, min(len(lines), start + max_lines)):
            line = lines[i]
            body.append(line)
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
        return body


class SingleTxManipulationDetector(BaseDetector):
    """Detect state that can be manipulated within a single transaction."""

    DETECTOR_ID = "SCWE-038-002"
    NAME = "Single-Transaction State Manipulation"
    DESCRIPTION = (
        "Detects balance-based or reserve-based calculations that read state "
        "which an attacker can manipulate within the same transaction using "
        "flash loans, enabling price manipulation or access bypass."
    )
    SCWE_ID = "SCWE-038"
    CWE_ID = "CWE-345"
    SEVERITY = Severity.HIGH
    CATEGORY = "flash_loan"

    DANGEROUS_PATTERNS = [
        (r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)', "contract's own token balance"),
        (r'address\s*\(\s*this\s*\)\.balance', "contract's ETH balance"),
        (r'totalAssets\s*\(\)', "totalAssets (vault share price)"),
        (r'getReserves\s*\(\)', "AMM reserves"),
        (r'totalSupply\s*\(\)\s*[==!><]', "totalSupply-based comparison"),
    ]

    SAFE_GUARDS = [
        "snapshot", "checkpoint", "TWAP", "twap", "_lastUpdateBlock",
        "blockNumber", "accrue", "nonReentrant",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")
        has_guard = any(g in source for g in self.SAFE_GUARDS)

        for pattern, desc in self.DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n")
                # Check if the usage is inside a view/pure function (less risky)
                func_context = self._get_enclosing_function(lines, line_no)
                if "view" in func_context or "pure" in func_context:
                    continue

                snippet = "\n".join(
                    lines[max(0, line_no - 1):min(len(lines), line_no + 3)]
                )
                severity = Severity.MEDIUM if has_guard else Severity.HIGH
                findings.append(self._make_finding(
                    title=f"Flash loan manipulable: {desc}",
                    description=(
                        f"The contract reads {desc} (line {line_no + 1}) in a "
                        "state-changing context. This value can be transiently "
                        "manipulated via flash loans within a single transaction, "
                        "potentially allowing price manipulation, share inflation, "
                        "or access control bypass."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    severity=severity,
                    remediation=(
                        "Protect against flash loan manipulation:\n"
                        "1. Use TWAP oracles instead of spot balances\n"
                        "2. Implement snapshot / checkpoint mechanisms\n"
                        "3. Add a delay between deposit and actions\n"
                        "4. Use `nonReentrant` guards on sensitive functions\n"
                        "5. Compare against cached values from previous blocks"
                    ),
                ))

        return findings

    def _get_enclosing_function(self, lines: list[str], line_no: int) -> str:
        """Walk backwards to find the enclosing function signature."""
        for i in range(line_no, max(0, line_no - 30), -1):
            if re.match(r'\s*function\s+', lines[i]):
                return lines[i]
        return ""


class FlashMintDetector(BaseDetector):
    """Detect flash mint patterns that could inflate token supply."""

    DETECTOR_ID = "SCWE-038-003"
    NAME = "Flash Mint Supply Inflation"
    DESCRIPTION = (
        "Detects ERC-20 contracts with flash mint capabilities where an "
        "attacker can temporarily inflate the token supply to manipulate "
        "governance votes, AMM prices, or other supply-dependent logic."
    )
    SCWE_ID = "SCWE-038"
    CWE_ID = "CWE-400"
    SEVERITY = Severity.HIGH
    CATEGORY = "flash_loan"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Detect flash mint pattern: mint + callback + burn in same tx
        has_flash_mint = bool(re.search(
            r'function\s+flashMint|function\s+flashLoan.*\n.*_mint\(',
            source, re.MULTILINE,
        ))

        if not has_flash_mint:
            # Check for mint without access control
            for match in re.finditer(r'function\s+(\w*[Mm]int\w*)\s*\(', source):
                func_name = match.group(1)
                line_no = source[:match.start()].count("\n")
                # Check for access restriction
                func_line = lines[line_no]
                has_restriction = bool(re.search(
                    r'onlyOwner|onlyMinter|onlyRole|require\s*\(\s*hasRole',
                    "\n".join(lines[line_no:min(len(lines), line_no + 5)]),
                ))
                if not has_restriction and "internal" not in func_line and "private" not in func_line:
                    snippet = "\n".join(
                        lines[line_no:min(len(lines), line_no + 5)]
                    )
                    findings.append(self._make_finding(
                        title=f"Unrestricted mint function `{func_name}`",
                        description=(
                            f"The mint function `{func_name}` at line {line_no + 1} "
                            "lacks access control. An attacker can call it to inflate "
                            "token supply, manipulating governance votes and AMM prices."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + 5,
                        snippet=snippet,
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Add access control to mint functions:\n"
                            "```solidity\n"
                            "function mint(address to, uint256 amount) external onlyMinter {\n"
                            "    _mint(to, amount);\n"
                            "}\n```"
                        ),
                    ))
            return findings

        # Flash mint exists — check for supply-dependent logic
        supply_patterns = [
            (r'totalSupply\(\)', "totalSupply()"),
            (r'balanceOf\(', "balanceOf()"),
            (r'getPriorVotes\(', "getPriorVotes()"),
            (r'getVotes\(', "getVotes()"),
        ]

        for pattern, desc in supply_patterns:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(
                    lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
                )
                findings.append(self._make_finding(
                    title=f"Flash mint can manipulate {desc}",
                    description=(
                        f"Contract has flash mint capability and reads {desc} "
                        f"at line {line_no + 1}. An attacker can temporarily inflate "
                        "supply via flash mint to manipulate this value within a "
                        "single transaction."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    severity=Severity.HIGH,
                    remediation=(
                        "Use snapshot-based reads or require that flash-minted "
                        "tokens are burned before any governance/AMM interactions:\n"
                        "- Use ERC20Snapshot or ERC20Votes (OpenZeppelin)\n"
                        "- Implement a cooldown period after minting\n"
                        "- Use block-delayed balance reads"
                    ),
                ))

        return findings


class BalanceDependentAccessDetector(BaseDetector):
    """Detect access control that depends on token balances."""

    DETECTOR_ID = "SCWE-038-004"
    NAME = "Balance-Dependent Access Control"
    DESCRIPTION = (
        "Detects access control checks based on token balances or liquidity "
        "positions, which can be bypassed via flash loans."
    )
    SCWE_ID = "SCWE-038"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.HIGH
    CATEGORY = "flash_loan"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # require(balanceOf(...) >= threshold)
        patterns = [
            (
                r'require\s*\([^)]*balanceOf\s*\([^)]*\)\s*>=',
                "balanceOf-based access check",
            ),
            (
                r'require\s*\([^)]*\.balanceOf\s*\(\s*msg\.sender\s*\)\s*>=',
                "sender balance gate",
            ),
            (
                r'if\s*\([^)]*balanceOf\s*\([^)]*\)\s*<',
                "balance-based conditional",
            ),
        ]

        for pattern, desc in patterns:
            for match in re.finditer(pattern, source, re.MULTILINE):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(
                    lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
                )
                findings.append(self._make_finding(
                    title=f"Flash loan bypassable: {desc}",
                    description=(
                        f"Access control at line {line_no + 1} uses a real-time "
                        f"balance check ({desc}). An attacker can flash loan tokens "
                        "to temporarily meet the threshold, execute privileged actions, "
                        "and return the tokens in the same transaction."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    remediation=(
                        "Use time-weighted or snapshot-based balance checks:\n"
                        "```solidity\n"
                        "// Use ERC20Votes for snapshot-based checks\n"
                        "require(\n"
                        "    token.getPastVotes(msg.sender, block.number - 1) >= threshold,\n"
                        "    \"Insufficient past balance\"\n"
                        ");\n```"
                    ),
                ))

        return findings

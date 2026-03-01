"""Token standard compliance detectors — SCWE-015, SCWE-016, SCWE-017.

Verify conformance to ERC-20, ERC-721, ERC-1155, and ERC-4626 and detect
subtle deviations that cause composability failures:
  - Missing return values on transfer/approve (non-compliant ERC-20)
  - Fee-on-transfer / rebasing token incompatibilities
  - ERC-777 hook reentrancy via tokensReceived
  - ERC-4626 first-depositor / inflation attacks
  - Missing ERC-165 supportsInterface
  - Permit / EIP-2612 replay risks
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class ERC20ComplianceDetector(BaseDetector):
    """Detect ERC-20 standard deviations that break composability."""

    DETECTOR_ID = "SCWE-015-001"
    NAME = "ERC-20 Non-Compliance"
    DESCRIPTION = (
        "Detects ERC-20 implementations that deviate from the standard, "
        "including missing return values, non-standard event emissions, "
        "and incorrect approve behavior."
    )
    SCWE_ID = "SCWE-015"
    CWE_ID = "CWE-573"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "token_standard"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Check if this is an ERC-20 token
        is_erc20 = bool(re.search(
            r'function\s+transfer\s*\(.*address.*uint', source
        ))
        if not is_erc20:
            return findings

        # 1. Missing return value on transfer
        for match in re.finditer(
            r'function\s+transfer\s*\([^)]*\)\s*(?:public|external)[^{]*\{',
            source, re.MULTILINE,
        ):
            line_no = source[:match.start()].count("\n")
            func_body = self._extract_body(lines, line_no)
            if "return" not in func_body and "returns (bool)" not in match.group():
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 5)])
                findings.append(self._make_finding(
                    title="ERC-20 transfer() missing return value",
                    description=(
                        "The transfer() function does not return a bool as required "
                        "by ERC-20. Many protocols (including Uniswap, Compound) check "
                        "the return value, so this token will fail in those contexts."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 5,
                    snippet=snippet,
                    remediation="Return true on success: `function transfer(...) external returns (bool) { ... return true; }`",
                ))

        # 2. Approve race condition (no increaseAllowance/decreaseAllowance)
        has_approve = bool(re.search(r'function\s+approve\s*\(', source))
        has_increase = bool(re.search(r'function\s+increaseAllowance\s*\(', source))
        if has_approve and not has_increase:
            for match in re.finditer(r'function\s+approve\s*\(', source):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 4)])
                findings.append(self._make_finding(
                    title="ERC-20 approve race condition",
                    description=(
                        "The token implements approve() without increaseAllowance/"
                        "decreaseAllowance. This allows a front-running attack where "
                        "a spender can spend both the old and new allowance when the "
                        "owner changes it."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    severity=Severity.LOW,
                    remediation=(
                        "Implement increaseAllowance/decreaseAllowance or use "
                        "OpenZeppelin's SafeERC20 pattern. Users should set allowance "
                        "to 0 before changing to a new value."
                    ),
                ))

        # 3. Fee-on-transfer detection
        for match in re.finditer(
            r'function\s+_transfer\s*\([^)]*\)\s*(?:internal|private)',
            source, re.MULTILINE,
        ):
            line_no = source[:match.start()].count("\n")
            func_body = self._extract_body(lines, line_no)
            if re.search(r'(fee|tax|burn)\s*=', func_body, re.IGNORECASE):
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 10)])
                findings.append(self._make_finding(
                    title="Fee-on-transfer token detected",
                    description=(
                        "This token applies a fee/tax during transfers. Many DeFi "
                        "protocols (Uniswap, compound depositories, bridges) assume "
                        "the received amount equals the sent amount. This causes "
                        "accounting errors and potential fund loss."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 10,
                    snippet=snippet,
                    severity=Severity.INFORMATIONAL,
                    remediation=(
                        "Document the fee-on-transfer behavior prominently. "
                        "DeFi integrations should measure balance changes:\n"
                        "```solidity\n"
                        "uint256 balBefore = token.balanceOf(address(this));\n"
                        "token.transferFrom(sender, address(this), amount);\n"
                        "uint256 received = token.balanceOf(address(this)) - balBefore;\n"
                        "```"
                    ),
                ))

        # 4. Rebasing token detection
        if re.search(r'rebase|_totalFragments|_gonBalance|_frag', source, re.IGNORECASE):
            findings.append(self._make_finding(
                title="Rebasing token detected",
                description=(
                    "This appears to be a rebasing token where balances change "
                    "automatically. Most DeFi protocols cannot handle rebasing tokens "
                    "correctly, leading to fund loss or incorrect accounting."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=1,
                end_line=1,
                severity=Severity.INFORMATIONAL,
                remediation=(
                    "Provide a wrapper token (e.g., wstETH for stETH) that does "
                    "not rebase. Document rebasing behavior and test with protocols."
                ),
            ))

        return findings

    def _extract_body(self, lines: list[str], start: int, max_lines: int = 50) -> str:
        depth = 0
        body_lines: list[str] = []
        started = False
        for i in range(start, min(len(lines), start + max_lines)):
            line = lines[i]
            body_lines.append(line)
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
        return "\n".join(body_lines)


class ERC721ComplianceDetector(BaseDetector):
    """Detect ERC-721 compliance issues."""

    DETECTOR_ID = "SCWE-016-001"
    NAME = "ERC-721 Non-Compliance"
    DESCRIPTION = (
        "Detects ERC-721 NFT implementations that deviate from the standard, "
        "including unsafe mints, missing receiver hooks, and incorrect event emissions."
    )
    SCWE_ID = "SCWE-016"
    CWE_ID = "CWE-573"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "token_standard"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        is_erc721 = bool(re.search(r'ERC721|function\s+ownerOf\s*\(', source))
        if not is_erc721:
            return findings

        # 1. Using _mint instead of _safeMint
        for match in re.finditer(r'_mint\s*\(', source):
            # Exclude _safeMint calls
            start = max(0, match.start() - 5)
            prefix = source[start:match.start()]
            if "safe" in prefix.lower():
                continue
            line_no = source[:match.start()].count("\n")
            snippet = "\n".join(lines[max(0, line_no - 1):min(len(lines), line_no + 2)])
            findings.append(self._make_finding(
                title="Unsafe ERC-721 _mint() usage",
                description=(
                    f"Using _mint() instead of _safeMint() at line {line_no + 1}. "
                    "If the recipient is a contract that doesn't implement "
                    "onERC721Received, the NFT will be permanently locked."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no + 1,
                end_line=line_no + 1,
                snippet=snippet,
                severity=Severity.MEDIUM,
                remediation="Use `_safeMint()` instead of `_mint()` to check if the receiver can handle ERC-721 tokens.",
            ))

        # 2. Missing supportsInterface
        has_supports_interface = bool(re.search(
            r'function\s+supportsInterface\s*\(', source
        ))
        if not has_supports_interface:
            findings.append(self._make_finding(
                title="Missing ERC-165 supportsInterface",
                description=(
                    "The ERC-721 contract does not implement supportsInterface(). "
                    "This is required by ERC-721 and used by marketplaces and wallets "
                    "to detect token types."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=1,
                end_line=1,
                severity=Severity.LOW,
                remediation=(
                    "Implement ERC-165:\n"
                    "```solidity\n"
                    "function supportsInterface(bytes4 interfaceId) public view override returns (bool) {\n"
                    "    return interfaceId == type(IERC721).interfaceId || super.supportsInterface(interfaceId);\n"
                    "}\n```"
                ),
            ))

        return findings


class ERC1155ComplianceDetector(BaseDetector):
    """Detect ERC-1155 compliance issues."""

    DETECTOR_ID = "SCWE-017-001"
    NAME = "ERC-1155 Non-Compliance"
    DESCRIPTION = (
        "Detects ERC-1155 multi-token implementations that deviate from the "
        "standard, including missing batch transfer events, missing onReceived "
        "checks, and incorrect URI handling."
    )
    SCWE_ID = "SCWE-017"
    CWE_ID = "CWE-573"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "token_standard"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        is_erc1155 = bool(re.search(r'ERC1155|safeBatchTransferFrom', source))
        if not is_erc1155:
            return findings

        # 1. Missing onERC1155Received check after transfer
        for match in re.finditer(
            r'function\s+safeTransferFrom\s*\([^)]*\)\s*(?:public|external)',
            source, re.MULTILINE,
        ):
            line_no = source[:match.start()].count("\n")
            func_end = min(len(lines), line_no + 30)
            func_text = "\n".join(lines[line_no:func_end])
            if "onERC1155Received" not in func_text:
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 5)])
                findings.append(self._make_finding(
                    title="Missing onERC1155Received callback check",
                    description=(
                        f"safeTransferFrom at line {line_no + 1} does not call "
                        "onERC1155Received on the recipient. Tokens sent to a "
                        "contract that cannot handle them will be permanently locked."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 5,
                    snippet=snippet,
                    remediation="Call `IERC1155Receiver(to).onERC1155Received(...)` after transfer and verify return value.",
                ))

        # 2. Missing TransferBatch event for batch operations
        has_batch_func = bool(re.search(r'function\s+safeBatchTransferFrom', source))
        has_batch_event = bool(re.search(r'emit\s+TransferBatch', source))
        if has_batch_func and not has_batch_event:
            findings.append(self._make_finding(
                title="Missing TransferBatch event emission",
                description=(
                    "The contract implements safeBatchTransferFrom but does not "
                    "emit TransferBatch events. This violates ERC-1155 and breaks "
                    "indexers, marketplaces, and wallets."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=1,
                end_line=1,
                severity=Severity.LOW,
                remediation="Emit `TransferBatch(operator, from, to, ids, amounts)` in batch transfer functions.",
            ))

        return findings


class ERC4626VaultDetector(BaseDetector):
    """Detect ERC-4626 tokenized vault vulnerabilities."""

    DETECTOR_ID = "SCWE-015-002"
    NAME = "ERC-4626 Vault Vulnerability"
    DESCRIPTION = (
        "Detects ERC-4626 vault implementations vulnerable to the "
        "first-depositor / share inflation attack, rounding issues, and "
        "donation attacks."
    )
    SCWE_ID = "SCWE-015"
    CWE_ID = "CWE-682"
    SEVERITY = Severity.HIGH
    CATEGORY = "token_standard"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        is_vault = bool(re.search(
            r'ERC4626|totalAssets|convertToShares|convertToAssets', source
        ))
        if not is_vault:
            return findings

        # 1. First depositor / inflation attack
        has_virtual_offset = bool(re.search(
            r'_decimalsOffset|virtualAssets|virtualShares|10\s*\*{2}\s*_decimalsOffset',
            source,
        ))
        has_min_deposit = bool(re.search(
            r'require.*totalSupply.*>|MIN_DEPOSIT|_dead[Ss]hares',
            source,
        ))

        if not has_virtual_offset and not has_min_deposit:
            findings.append(self._make_finding(
                title="ERC-4626 first-depositor inflation attack",
                description=(
                    "The vault does not implement virtual offset (ERC-4626 decimals "
                    "offset) or minimum deposit protection. An attacker can:\n"
                    "1. Deposit 1 wei to receive 1 share\n"
                    "2. Donate a large amount of assets directly to the vault\n"
                    "3. Subsequent depositors receive 0 shares due to rounding\n"
                    "4. Attacker redeems their 1 share for all assets"
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=1,
                end_line=1,
                severity=Severity.HIGH,
                remediation=(
                    "Implement OpenZeppelin's virtual offset pattern:\n"
                    "```solidity\n"
                    "function _decimalsOffset() internal pure override returns (uint8) {\n"
                    "    return 3; // or higher for more protection\n"
                    "}\n```\n"
                    "Or seed the vault with a minimum initial deposit."
                ),
            ))

        # 2. Rounding direction issues
        for func_name in ["convertToShares", "convertToAssets", "previewDeposit",
                          "previewRedeem", "previewMint", "previewWithdraw"]:
            pattern = rf'function\s+{func_name}\s*\('
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n")
                func_end = min(len(lines), line_no + 15)
                func_text = "\n".join(lines[line_no:func_end])
                # Check for explicit rounding direction
                has_rounding = bool(re.search(
                    r'Math\.Rounding|mulDiv.*rounding|ceilDiv|\.ceil',
                    func_text,
                ))
                if not has_rounding and "mulDiv" in func_text:
                    snippet = "\n".join(lines[line_no:min(len(lines), line_no + 5)])
                    findings.append(self._make_finding(
                        title=f"Missing rounding direction in {func_name}",
                        description=(
                            f"{func_name} uses division without explicit rounding "
                            f"direction. ERC-4626 requires deposits/mints to round "
                            f"against the depositor and withdrawals/redeems to round "
                            f"against the redeemer to prevent value extraction."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + 5,
                        snippet=snippet,
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Use OpenZeppelin's Math.mulDiv with explicit rounding:\n"
                            "- Deposits/mints: round DOWN (against depositor)\n"
                            "- Withdrawals/redeems: round UP (against redeemer)"
                        ),
                    ))

        return findings


class ERC777HookDetector(BaseDetector):
    """Detect ERC-777 hook-based reentrancy risks."""

    DETECTOR_ID = "SCWE-015-003"
    NAME = "ERC-777 Hook Reentrancy"
    DESCRIPTION = (
        "Detects interactions with ERC-777 tokens whose tokensToSend and "
        "tokensReceived hooks can trigger reentrancy in unprepared contracts."
    )
    SCWE_ID = "SCWE-015"
    CWE_ID = "CWE-841"
    SEVERITY = Severity.HIGH
    CATEGORY = "token_standard"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # ERC-777 patterns
        is_erc777 = bool(re.search(
            r'IERC777|ERC777|tokensReceived|tokensToSend|_callTokensToSend|_callTokensReceived',
            source,
        ))

        if not is_erc777:
            # Check if the contract interacts with unknown tokens without reentrancy guard
            has_arbitrary_transfer = bool(re.search(
                r'IERC20\s*\(\s*\w+\s*\)\s*\.transfer', source
            ))
            has_reentrancy_guard = "nonReentrant" in source or "ReentrancyGuard" in source

            if has_arbitrary_transfer and not has_reentrancy_guard:
                for match in re.finditer(
                    r'IERC20\s*\(\s*\w+\s*\)\s*\.transfer', source
                ):
                    line_no = source[:match.start()].count("\n")
                    snippet = "\n".join(
                        lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
                    )
                    findings.append(self._make_finding(
                        title="Arbitrary token interaction without reentrancy guard",
                        description=(
                            f"The contract transfers arbitrary tokens (line {line_no + 1}) "
                            "without ReentrancyGuard. If the token is ERC-777 compatible, "
                            "the transfer will trigger tokensToSend/tokensReceived hooks, "
                            "enabling reentrancy."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + 1,
                        snippet=snippet,
                        remediation=(
                            "Add ReentrancyGuard to functions that handle arbitrary tokens:\n"
                            "```solidity\n"
                            "function deposit(IERC20 token, uint256 amount) external nonReentrant {\n"
                            "    token.safeTransferFrom(msg.sender, address(this), amount);\n"
                            "}\n```"
                        ),
                    ))

        return findings


class PermitReplayDetector(BaseDetector):
    """Detect EIP-2612 permit replay vulnerabilities."""

    DETECTOR_ID = "SCWE-015-004"
    NAME = "Permit / EIP-2612 Replay"
    DESCRIPTION = (
        "Detects permit implementations vulnerable to replay attacks due to "
        "missing or incorrect nonce handling, chain ID validation, or "
        "deadline enforcement."
    )
    SCWE_ID = "SCWE-015"
    CWE_ID = "CWE-294"
    SEVERITY = Severity.HIGH
    CATEGORY = "token_standard"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        has_permit = bool(re.search(r'function\s+permit\s*\(', source))
        if not has_permit:
            return findings

        for match in re.finditer(r'function\s+permit\s*\(', source):
            line_no = source[:match.start()].count("\n")
            func_end = min(len(lines), line_no + 30)
            func_text = "\n".join(lines[line_no:func_end])

            issues: list[str] = []

            if "nonce" not in func_text.lower() and "_nonces" not in func_text:
                issues.append("missing nonce increment — permits can be replayed")
            if "deadline" not in func_text.lower() and "expiry" not in func_text.lower():
                issues.append("missing deadline check — permits never expire")
            if "block.chainid" not in func_text and "DOMAIN_SEPARATOR" not in func_text:
                issues.append("missing chain ID — permits can be replayed cross-chain")
            if "ecrecover" in func_text and "address(0)" not in func_text:
                issues.append("no ecrecover zero-address check — invalid signatures accepted")

            if issues:
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 10)])
                findings.append(self._make_finding(
                    title="EIP-2612 permit vulnerability",
                    description=(
                        f"The permit function at line {line_no + 1} has the following "
                        f"issues:\n" + "\n".join(f"  - {i}" for i in issues)
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 15,
                    snippet=snippet,
                    remediation=(
                        "Use OpenZeppelin's ERC20Permit which handles nonces, "
                        "deadlines, and domain separators correctly. If implementing "
                        "manually, ensure:\n"
                        "1. Nonce is incremented per-use\n"
                        "2. Deadline is checked against block.timestamp\n"
                        "3. DOMAIN_SEPARATOR includes block.chainid\n"
                        "4. ecrecover result != address(0)"
                    ),
                ))

        return findings

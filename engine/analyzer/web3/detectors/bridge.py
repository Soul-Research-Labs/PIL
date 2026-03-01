"""Cross-chain bridge vulnerability detectors — SCWE-050.

Detects patterns specific to cross-chain bridges and messaging protocols:
  - Missing source-chain validation in message receivers
  - Replay attacks from missing nonce / message-hash tracking
  - Unvalidated relayer / oracle inputs
  - Incomplete bridge message verification
  - Unauthorized mint/unlock after bridging
  - Lack of pause/emergency mechanisms
  - Double-spend via race between chains
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


# ── Helpers ──────────────────────────────────────────────────────────────

_BRIDGE_INDICATORS = [
    "bridge", "Bridge", "crosschain", "CrossChain", "cross_chain",
    "LayerZero", "lzReceive", "Axelar", "Wormhole", "Hyperlane",
    "CCIP", "ccipReceive", "Multichain", "anyCall", "Stargate",
    "Celer", "sgReceive", "IMessageRecipient", "receiveMessage",
    "onMessageReceived", "_nonblockingLzReceive", "sendMessage",
    "relayMessage", "executeMessage", "processMessage",
]


def _is_bridge_contract(source: str) -> bool:
    """Heuristic: does the source look like a bridge / cross-chain contract?"""
    return any(kw in source for kw in _BRIDGE_INDICATORS)


def _extract_function_body(
    lines: list[str], start: int, max_lines: int = 100,
) -> list[str]:
    """Extract lines from *start* to the function's closing brace."""
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


# ── 1. Missing source-chain / sender validation ─────────────────────────


class BridgeSourceChainValidation(BaseDetector):
    """Detect bridge receive functions that do not validate source chain."""

    DETECTOR_ID = "SCWE-050-001"
    NAME = "Missing Source-Chain Validation"
    DESCRIPTION = (
        "Detects cross-chain message receiver functions that do not validate "
        "the source chain-ID or trusted remote address, allowing an attacker "
        "to send spoofed messages from an untrusted chain."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-346"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "bridge"
    CONFIDENCE = 0.85

    # Receiver functions (regex, human name)
    _RECEIVERS: list[tuple[str, str]] = [
        (r"function\s+lzReceive\s*\(", "LayerZero lzReceive"),
        (r"function\s+_nonblockingLzReceive\s*\(", "LayerZero _nonblockingLzReceive"),
        (r"function\s+sgReceive\s*\(", "Stargate sgReceive"),
        (r"function\s+ccipReceive\s*\(", "Chainlink CCIP ccipReceive"),
        (r"function\s+_ccipReceive\s*\(", "Chainlink CCIP _ccipReceive"),
        (r"function\s+receiveMessage\s*\(", "Generic receiveMessage"),
        (r"function\s+onMessageReceived\s*\(", "Generic onMessageReceived"),
        (r"function\s+processMessage\s*\(", "Generic processMessage"),
        (r"function\s+executeMessage\s*\(", "Celer executeMessage"),
        (r"function\s+_execute\s*\(", "Axelar _execute"),
        (r"function\s+receiveWormholeMessages\s*\(", "Wormhole receiveWormholeMessages"),
    ]

    # Validation patterns we expect to see inside the function body
    _CHAIN_CHECKS: list[str] = [
        r"require\s*\([^)]*srcChainId",
        r"require\s*\([^)]*sourceChainId",
        r"require\s*\([^)]*_srcChainId",
        r"require\s*\([^)]*chainId",
        r"require\s*\([^)]*sourceChain",
        r"trustedRemoteLookup",
        r"trustedRemote",
        r"isTrustedRemote",
        r"onlyTrustedRemote",
        r"allowedSourceChains",
        r"_trustedSenders",
        r"sourceChainSelector\s*==",
        r"if\s*\([^)]*srcChainId\s*!=",
        r"if\s*\([^)]*sourceChain\s*!=",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        if not _is_bridge_contract(source):
            return findings

        for pattern, name in self._RECEIVERS:
            for match in re.finditer(pattern, source):
                line_no = source[: match.start()].count("\n")
                func_body = _extract_function_body(lines, line_no)
                func_text = "\n".join(func_body)

                has_chain_check = any(
                    re.search(v, func_text) for v in self._CHAIN_CHECKS
                )

                if not has_chain_check:
                    snippet = "\n".join(lines[line_no: min(len(lines), line_no + 8)])
                    findings.append(
                        self._make_finding(
                            title=f"No source-chain validation in {name}",
                            description=(
                                f"The {name} callback at line {line_no + 1} does not "
                                "validate the source chain ID or trusted remote address. "
                                "An attacker can deploy a contract on an untrusted chain "
                                "and send malicious messages that will be accepted."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=line_no + 1,
                            end_line=line_no + len(func_body),
                            snippet=snippet,
                            remediation=(
                                "Validate the source chain and sender:\n"
                                "```solidity\n"
                                "require(\n"
                                "    trustedRemoteLookup[srcChainId] == srcAddress,\n"
                                '    "Untrusted source"\n'
                                ");\n```\n"
                                "Or use the protocol's built-in trust mechanism "
                                "(e.g., LayerZero `setTrustedRemote`)."
                            ),
                        )
                    )

        return findings


# ── 2. Bridge replay attacks ────────────────────────────────────────────


class BridgeReplayDetector(BaseDetector):
    """Detect bridge receivers vulnerable to message replay."""

    DETECTOR_ID = "SCWE-050-002"
    NAME = "Bridge Message Replay"
    DESCRIPTION = (
        "Detects cross-chain message handlers that do not track processed "
        "message hashes or nonces, allowing the same message to be replayed "
        "multiple times to mint/unlock tokens repeatedly."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-294"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "bridge"
    CONFIDENCE = 0.80

    _REPLAY_GUARDS: list[str] = [
        r"processedMessages\[",
        r"executedMessages\[",
        r"usedNonces\[",
        r"consumedMessages\[",
        r"isTransferCompleted\[",
        r"nonceUsed\[",
        r"claimed\[",
        r"processedHashes\[",
        r"_messageDelivered\[",
        r"executed\[.*\]\s*=\s*true",
        r"require\s*\(\s*!.*processed",
        r"require\s*\(\s*!.*executed",
        r"require\s*\(\s*!.*claimed",
        r"nonce\s*\+\+",
        r"_nonce\s*\+\+",
    ]

    # Functions that mint or unlock (high-value targets for replay)
    _MINT_UNLOCK = [
        r"\b_mint\s*\(",
        r"\bmint\s*\(",
        r"\.transfer\s*\(",
        r"\.safeTransfer\s*\(",
        r"unlock\(",
        r"release\(",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        if not _is_bridge_contract(source):
            return findings

        # Find receive / execute functions that mint or unlock
        func_re = re.compile(
            r"function\s+(receive\w*|execute\w*|process\w*|lzReceive|"
            r"_nonblockingLzReceive|sgReceive|ccipReceive|_ccipReceive|"
            r"onMessageReceived|_execute|receiveWormholeMessages)\s*\("
        )

        for match in func_re.finditer(source):
            func_name = match.group(1)
            line_no = source[: match.start()].count("\n")
            func_body = _extract_function_body(lines, line_no)
            func_text = "\n".join(func_body)

            # Only flag if the function performs a high-value action
            has_mint_unlock = any(
                re.search(p, func_text) for p in self._MINT_UNLOCK
            )
            if not has_mint_unlock:
                continue

            has_replay_guard = any(
                re.search(g, func_text) for g in self._REPLAY_GUARDS
            )

            if not has_replay_guard:
                snippet = "\n".join(lines[line_no: min(len(lines), line_no + 8)])
                findings.append(
                    self._make_finding(
                        title=f"Replay-vulnerable bridge handler `{func_name}`",
                        description=(
                            f"`{func_name}` at line {line_no + 1} mints or unlocks "
                            "tokens without tracking processed message hashes or "
                            "nonces. A relayer or attacker who obtains a valid message "
                            "can replay it to extract funds repeatedly."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + len(func_body),
                        snippet=snippet,
                        remediation=(
                            "Track processed messages to prevent replay:\n"
                            "```solidity\n"
                            "mapping(bytes32 => bool) public processedMessages;\n\n"
                            "function _processMessage(bytes32 msgHash, ...) internal {\n"
                            '    require(!processedMessages[msgHash], "Already processed");\n'
                            "    processedMessages[msgHash] = true;\n"
                            "    // ... mint / unlock ...\n"
                            "}\n```"
                        ),
                    )
                )

        return findings


# ── 3. Unvalidated relayer / oracle input ────────────────────────────────


class BridgeRelayerValidation(BaseDetector):
    """Detect bridges that accept messages from any relayer without auth."""

    DETECTOR_ID = "SCWE-050-003"
    NAME = "Unvalidated Bridge Relayer"
    DESCRIPTION = (
        "Detects bridge receiver functions callable by any address without "
        "restricting to an authorized relayer, AMB, or messaging endpoint. "
        "This allows anyone to forge cross-chain messages."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "bridge"
    CONFIDENCE = 0.82

    _RELAYER_CHECKS: list[str] = [
        r"require\s*\(\s*msg\.sender\s*==\s*(endpoint|relayer|bridge|messenger|amb)",
        r"onlyEndpoint",
        r"onlyRelayer",
        r"onlyBridge",
        r"onlyMessenger",
        r"onlyAMB",
        r"onlyCrossChainSender",
        r"msg\.sender\s*==\s*address\s*\(\s*endpoint",
        r"msg\.sender\s*==\s*address\s*\(\s*lzEndpoint",
        r"msg\.sender\s*==\s*address\s*\(\s*getRouter",
        r"_onlyRouter\(",
        r"isSenderAuthorised",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        if not _is_bridge_contract(source):
            return findings

        # External/public receive-style functions
        func_re = re.compile(
            r"function\s+(receive\w*|execute\w*|process\w*|relay\w*|"
            r"deliver\w*|handleMessage\w*|onMessage\w*)\s*\([^)]*\)"
            r"\s+(external|public)"
        )

        for match in func_re.finditer(source):
            func_name = match.group(1)
            line_no = source[: match.start()].count("\n")
            func_body = _extract_function_body(lines, line_no)
            func_text = "\n".join(func_body)

            has_relayer_check = any(
                re.search(c, func_text, re.IGNORECASE) for c in self._RELAYER_CHECKS
            )

            if not has_relayer_check:
                snippet = "\n".join(lines[line_no: min(len(lines), line_no + 6)])
                findings.append(
                    self._make_finding(
                        title=f"Unrestricted bridge receiver `{func_name}`",
                        description=(
                            f"`{func_name}` at line {line_no + 1} is externally callable "
                            "without restricting the caller to the authorized bridge "
                            "endpoint or relayer. Any account can forge cross-chain "
                            "messages and trigger token mints, unlocks, or state changes."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + len(func_body),
                        snippet=snippet,
                        remediation=(
                            "Restrict the caller to the protocol endpoint:\n"
                            "```solidity\n"
                            "modifier onlyEndpoint() {\n"
                            '    require(msg.sender == address(endpoint), "Not endpoint");\n'
                            "    _;\n"
                            "}\n\n"
                            "function receiveMessage(...) external onlyEndpoint {\n"
                            "    // ...\n"
                            "}\n```"
                        ),
                    )
                )

        return findings


# ── 4. Unauthorized mint/unlock after bridge ─────────────────────────────


class BridgeMintUnlockAuth(BaseDetector):
    """Detect bridge mint/unlock functions lacking proper authorization."""

    DETECTOR_ID = "SCWE-050-004"
    NAME = "Unauthorized Bridge Mint/Unlock"
    DESCRIPTION = (
        "Detects public mint or unlock functions in bridge contracts that "
        "lack proper access control, allowing unauthorized token creation "
        "or fund release."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-862"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "bridge"
    CONFIDENCE = 0.88

    _AUTH_PATTERNS: list[str] = [
        r"onlyBridge",
        r"onlyMinter",
        r"onlyRole",
        r"onlyOwner",
        r"onlyEndpoint",
        r"onlyRelayer",
        r"require\s*\(\s*msg\.sender\s*==",
        r"require\s*\(\s*hasRole\s*\(",
        r"_checkRole\(",
        r"internal\b",
        r"private\b",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        if not _is_bridge_contract(source):
            return findings

        # Look for public/external mint or unlock functions
        func_re = re.compile(
            r"function\s+(mint\w*|unlock\w*|release\w*|withdraw\w*Bridge\w*)"
            r"\s*\([^)]*\)\s*(external|public)"
        )

        for match in func_re.finditer(source):
            func_name = match.group(1)
            line_no = source[: match.start()].count("\n")
            func_body = _extract_function_body(lines, line_no)
            func_text = "\n".join(func_body)
            func_sig = lines[line_no] if line_no < len(lines) else ""

            has_auth = any(
                re.search(p, func_text) or re.search(p, func_sig)
                for p in self._AUTH_PATTERNS
            )

            if not has_auth:
                snippet = "\n".join(lines[line_no: min(len(lines), line_no + 6)])
                findings.append(
                    self._make_finding(
                        title=f"Unprotected bridge `{func_name}` function",
                        description=(
                            f"`{func_name}` at line {line_no + 1} is publicly callable "
                            "without access control in a bridge contract. An attacker "
                            "can call it directly to mint wrapped tokens or unlock "
                            "native tokens without a legitimate cross-chain transfer."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + len(func_body),
                        snippet=snippet,
                        remediation=(
                            "Restrict mint/unlock to the bridge's message handler:\n"
                            "```solidity\n"
                            "function mint(address to, uint256 amount) external onlyBridge {\n"
                            "    _mint(to, amount);\n"
                            "}\n```\n"
                            "Alternatively, make the function `internal` and call it "
                            "only from the validated message receiver."
                        ),
                    )
                )

        return findings


# ── 5. Missing emergency pause ───────────────────────────────────────────


class BridgeEmergencyPause(BaseDetector):
    """Detect bridge contracts without emergency pause capability."""

    DETECTOR_ID = "SCWE-050-005"
    NAME = "Bridge Missing Emergency Pause"
    DESCRIPTION = (
        "Detects cross-chain bridge contracts that lack a pause/unpause "
        "mechanism. Bridges are high-value targets and must be pausable "
        "to respond to exploits, chain re-orgs, or relayer compromise."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-693"
    SEVERITY = Severity.HIGH
    CATEGORY = "bridge"
    CONFIDENCE = 0.85

    _PAUSE_INDICATORS: list[str] = [
        r"Pausable",
        r"whenNotPaused",
        r"paused\s*\(\)",
        r"function\s+pause\s*\(",
        r"_pause\s*\(\)",
        r"emergencyStop",
        r"circuit[Bb]reaker",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code

        if not _is_bridge_contract(source):
            return findings

        has_pause = any(
            re.search(p, source) for p in self._PAUSE_INDICATORS
        )

        if not has_pause:
            findings.append(
                self._make_finding(
                    title="Bridge contract lacks emergency pause",
                    description=(
                        "This cross-chain bridge contract does not implement a "
                        "Pausable pattern or emergency stop mechanism. If a "
                        "vulnerability is discovered, there is no way to halt "
                        "operations while a fix is deployed, potentially leading "
                        "to catastrophic fund loss."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=1,
                    end_line=1,
                    snippet="",
                    remediation=(
                        "Implement OpenZeppelin's Pausable and add `whenNotPaused` "
                        "to all bridge functions:\n"
                        "```solidity\n"
                        "import {Pausable} from \"@openzeppelin/contracts/security/Pausable.sol\";\n\n"
                        "contract Bridge is Pausable {\n"
                        "    function deposit(...) external whenNotPaused { ... }\n"
                        "    function pause() external onlyGuardian { _pause(); }\n"
                        "}\n```"
                    ),
                )
            )

        return findings


# ── 6. Incomplete message verification ───────────────────────────────────


class BridgeMessageVerification(BaseDetector):
    """Detect bridge messages decoded without signature/proof verification."""

    DETECTOR_ID = "SCWE-050-006"
    NAME = "Incomplete Bridge Message Verification"
    DESCRIPTION = (
        "Detects bridge receivers that decode and act on message payloads "
        "without verifying a cryptographic signature, Merkle proof, or "
        "validator attestation, allowing message forgery."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-347"
    SEVERITY = Severity.HIGH
    CATEGORY = "bridge"
    CONFIDENCE = 0.78

    _DECODE_PATTERNS: list[str] = [
        r"abi\.decode\s*\(",
        r"abi\.decodePacked\s*\(",
        r"_payload\s*\[",
        r"Bytes\.slice\(",
    ]

    _VERIFICATION_PATTERNS: list[str] = [
        r"ecrecover\s*\(",
        r"ECDSA\.recover\s*\(",
        r"SignatureChecker",
        r"verifyProof\s*\(",
        r"verifyMerkle",
        r"verifySignature",
        r"verifyAttestation",
        r"_verifyMessage\(",
        r"_validateMessage\(",
        r"verifyHeaderAndTxProof",
        r"keccak256.*signatures",
        r"IMessageVerifier",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        if not _is_bridge_contract(source):
            return findings

        # Global check: does the contract verify messages at all?
        has_verification = any(
            re.search(p, source) for p in self._VERIFICATION_PATTERNS
        )

        if has_verification:
            return findings  # Contract has some verification mechanism

        # Find functions that decode payloads
        func_re = re.compile(
            r"function\s+(\w*[Rr]eceive\w*|\w*[Ee]xecute\w*|"
            r"\w*[Pp]rocess\w*|_nonblockingLzReceive|_execute|"
            r"lzReceive|sgReceive|ccipReceive)\s*\("
        )

        for match in func_re.finditer(source):
            func_name = match.group(1)
            line_no = source[: match.start()].count("\n")
            func_body = _extract_function_body(lines, line_no)
            func_text = "\n".join(func_body)

            has_decode = any(
                re.search(d, func_text) for d in self._DECODE_PATTERNS
            )

            if has_decode:
                snippet = "\n".join(lines[line_no: min(len(lines), line_no + 8)])
                findings.append(
                    self._make_finding(
                        title=f"Unverified message payload in `{func_name}`",
                        description=(
                            f"`{func_name}` at line {line_no + 1} decodes and acts on "
                            "a cross-chain message payload without any visible "
                            "cryptographic verification (signature, Merkle proof, or "
                            "validator attestation). If the relayer or messaging layer "
                            "is compromised, forged messages will be accepted."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + len(func_body),
                        snippet=snippet,
                        severity=Severity.HIGH,
                        remediation=(
                            "Verify the message before decoding:\n"
                            "```solidity\n"
                            "bytes32 msgHash = keccak256(payload);\n"
                            "address signer = ECDSA.recover(msgHash, signature);\n"
                            'require(isValidator[signer], "Invalid signer");\n'
                            "// Now safe to decode\n"
                            "(address to, uint256 amount) = abi.decode(payload, (address, uint256));\n"
                            "```"
                        ),
                    )
                )

        return findings


# ── 7. Bridge deposit without amount validation ─────────────────────────


class BridgeDepositValidation(BaseDetector):
    """Detect bridge deposit functions that lack amount/token validation."""

    DETECTOR_ID = "SCWE-050-007"
    NAME = "Bridge Deposit Without Validation"
    DESCRIPTION = (
        "Detects bridge deposit/lock functions that accept arbitrary amounts "
        "or token addresses without validation, enabling zero-amount griefing "
        "or unsupported token deposits that may corrupt accounting."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-20"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "bridge"
    CONFIDENCE = 0.80

    _VALIDATION_PATTERNS: list[str] = [
        r"require\s*\(\s*amount\s*>\s*0",
        r"require\s*\(\s*_amount\s*>\s*0",
        r"require\s*\(\s*msg\.value\s*>\s*0",
        r"amount\s*!=\s*0",
        r"_amount\s*!=\s*0",
        r"supportedTokens\[",
        r"allowedTokens\[",
        r"whitelistedTokens\[",
        r"isTokenSupported\(",
        r"minAmount",
        r"maxAmount",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        if not _is_bridge_contract(source):
            return findings

        func_re = re.compile(
            r"function\s+(deposit\w*|lock\w*|send\w*|bridge\w*)\s*\("
            r"[^)]*\)\s*(external|public)\s*(payable)?"
        )

        for match in func_re.finditer(source):
            func_name = match.group(1)
            line_no = source[: match.start()].count("\n")
            func_body = _extract_function_body(lines, line_no)
            func_text = "\n".join(func_body)

            has_validation = any(
                re.search(p, func_text) for p in self._VALIDATION_PATTERNS
            )

            if not has_validation:
                snippet = "\n".join(lines[line_no: min(len(lines), line_no + 6)])
                findings.append(
                    self._make_finding(
                        title=f"Bridge `{func_name}` lacks input validation",
                        description=(
                            f"`{func_name}` at line {line_no + 1} does not validate "
                            "the deposit amount or token address. Zero-amount deposits "
                            "can grief the relayer network, and unsupported tokens "
                            "may brick the bridge accounting on the destination chain."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + len(func_body),
                        snippet=snippet,
                        remediation=(
                            "Validate deposit inputs:\n"
                            "```solidity\n"
                            'require(amount > 0, "Zero amount");\n'
                            'require(amount <= maxDeposit, "Exceeds max");\n'
                            'require(supportedTokens[token], "Unsupported token");\n'
                            "```"
                        ),
                    )
                )

        return findings


# ── 8. Bridge fund drainage via imbalanced accounting ────────────────────


class BridgeAccountingImbalance(BaseDetector):
    """Detect bridges where lock/mint and burn/unlock are not balanced."""

    DETECTOR_ID = "SCWE-050-008"
    NAME = "Bridge Accounting Imbalance"
    DESCRIPTION = (
        "Detects bridge contracts where the deposit/lock logic does not "
        "maintain an explicit accounting ledger (e.g., totalLocked mapping), "
        "making it impossible to verify 1:1 backing and enabling silent "
        "drainage through rounding or fee calculation errors."
    )
    SCWE_ID = "SCWE-050"
    CWE_ID = "CWE-682"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "bridge"
    CONFIDENCE = 0.72

    _ACCOUNTING_PATTERNS: list[str] = [
        r"totalLocked\[",
        r"lockedAmounts\[",
        r"totalDeposited",
        r"deposits\[.*\]\s*\+=",
        r"bridgeBalance\[",
        r"_balances\[.*\]\s*\+=",
        r"event\s+Deposit.*amount",
        r"emit\s+Deposit\s*\(",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code

        if not _is_bridge_contract(source):
            return findings

        # Check if there's a lock function
        has_lock = bool(
            re.search(r"function\s+(deposit|lock|bridge)\w*\s*\(", source)
        )
        if not has_lock:
            return findings

        has_accounting = any(
            re.search(p, source) for p in self._ACCOUNTING_PATTERNS
        )

        if not has_accounting:
            findings.append(
                self._make_finding(
                    title="Bridge lacks explicit fund accounting",
                    description=(
                        "This bridge contract locks/releases funds without maintaining "
                        "an explicit accounting ledger (e.g., totalLocked mapping or "
                        "deposit events). Without on-chain accounting, it is impossible "
                        "to verify that minted wrapped tokens are fully backed, and "
                        "rounding or fee errors can silently drain the bridge."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=1,
                    end_line=1,
                    snippet="",
                    remediation=(
                        "Maintain explicit fund accounting:\n"
                        "```solidity\n"
                        "mapping(address => uint256) public totalLocked;\n\n"
                        "function deposit(address token, uint256 amount) external {\n"
                        "    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);\n"
                        "    totalLocked[token] += amount;\n"
                        "    emit Deposit(token, msg.sender, amount);\n"
                        "}\n```"
                    ),
                )
            )

        return findings

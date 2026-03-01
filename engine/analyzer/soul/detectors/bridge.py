"""Soul Protocol bridge and cross-chain vulnerability detectors.

Detects:
  - Bridge relay replay attacks
  - Missing circuit breaker integration
  - Cross-chain message validation gaps
  - Atomic swap fund-loss patterns
  - Rate limiter bypass
  - Watchtower absence
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class BridgeRelayReplayDetector(BaseDetector):
    """Detect bridge relay replay vulnerabilities."""

    DETECTOR_ID = "SOUL-BRIDGE-001"
    NAME = "Soul Bridge Relay Replay"
    DESCRIPTION = "Detects bridge relay functions vulnerable to message replay attacks"
    SCWE_ID = "SOUL-040"
    CWE_ID = "CWE-294"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-bridge"
    CONFIDENCE = 0.85

    _RELAY = re.compile(
        r"(relay|receiveMessage|processMessage|executeRelay|onMessageReceived)",
        re.IGNORECASE,
    )
    _NONCE_CHECK = re.compile(
        r"(nonce|messageId|processedMessages|usedHashes|require.*!.*processed)",
        re.IGNORECASE,
    )
    _SOURCE_VERIFY = re.compile(
        r"(msg\.sender\s*==\s*bridge|_verifySender|onlyBridge|trustedRemote)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        bridge_indicators = [
            "BridgeAdapter", "CrossChain", "L2Messenger", "relay",
            "LayerZero", "Hyperlane", "ProofHub",
        ]
        is_bridge = any(ind in context.source_code for ind in bridge_indicators)

        if not is_bridge:
            return findings

        for i, line in enumerate(lines):
            if self._RELAY.search(line) and "function" in line:
                body = "\n".join(lines[i:min(i + 30, len(lines))])

                has_nonce = bool(self._NONCE_CHECK.search(body))
                has_source = bool(self._SOURCE_VERIFY.search(body))

                if not has_nonce:
                    findings.append(self._make_finding(
                        title="Bridge relay lacks replay protection",
                        description=(
                            f"Bridge relay function at line {i + 1} does not check "
                            f"message nonces or track processed messages. Without replay "
                            f"protection, the same cross-chain message could be executed "
                            f"multiple times, draining bridge funds."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        remediation=(
                            "Track processed messages: "
                            "`mapping(bytes32 => bool) processedMessages; "
                            "bytes32 hash = keccak256(abi.encode(sourceChain, nonce, data)); "
                            "require(!processedMessages[hash]); processedMessages[hash] = true;`"
                        ),
                    ))

                if not has_source:
                    findings.append(self._make_finding(
                        title="Bridge relay doesn't verify message source",
                        description=(
                            f"Bridge relay at line {i + 1} does not verify the message "
                            f"sender. Without source verification, any address could send "
                            f"fake cross-chain messages."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Verify message source: `require(msg.sender == trustedBridge)` "
                            "or use bridge-specific origin verification."
                        ),
                    ))

        return findings


class MissingCircuitBreakerDetector(BaseDetector):
    """Detect bridge operations without circuit breaker protection."""

    DETECTOR_ID = "SOUL-BRIDGE-002"
    NAME = "Soul Missing Circuit Breaker"
    DESCRIPTION = "Detects bridge operations lacking circuit breaker integration"
    SCWE_ID = "SOUL-042"
    CWE_ID = "CWE-754"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-bridge"
    CONFIDENCE = 0.75

    _BRIDGE_OP = re.compile(
        r"function\s+(relay|bridge|transfer|send|receive)\w*\s*\(",
        re.IGNORECASE,
    )
    _CIRCUIT_BREAKER = re.compile(
        r"(circuitBreaker|whenNotPaused|_checkCircuit|BridgeCircuitBreaker|notTripped)",
        re.IGNORECASE,
    )
    _VOLUME_CHECK = re.compile(
        r"(maxVolume|volumeLimit|dailyLimit|_checkVolume|exceedsLimit)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._BRIDGE_OP.search(line):
                body = "\n".join(lines[i:min(i + 20, len(lines))])

                has_cb = bool(self._CIRCUIT_BREAKER.search(body))
                has_volume = bool(self._VOLUME_CHECK.search(body))

                if not has_cb:
                    findings.append(self._make_finding(
                        title="Bridge operation lacks circuit breaker",
                        description=(
                            f"Bridge operation at line {i + 1} does not integrate with "
                            f"BridgeCircuitBreaker. If an exploit drains funds, there's "
                            f"no automatic pause mechanism. Soul Protocol requires all "
                            f"bridge operations to check the circuit breaker state."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Integrate circuit breaker: "
                            "`modifier checkCircuitBreaker() { "
                            "require(!circuitBreaker.isTripped(), \"Circuit breaker active\"); _; "
                            "circuitBreaker.recordOperation(msg.value); }`"
                        ),
                    ))

                if not has_volume:
                    findings.append(self._make_finding(
                        title="Bridge operation lacks volume checks",
                        description=(
                            f"Bridge operation at line {i + 1} does not check transfer "
                            f"volume limits. Without volume monitoring, a single attacker "
                            f"could drain the bridge in one large transaction."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Add volume limit: "
                            "`require(dailyVolume[today()] + amount <= MAX_DAILY_VOLUME)`"
                        ),
                    ))

        return findings


class AtomicSwapFundLossDetector(BaseDetector):
    """Detect fund-loss patterns in atomic swaps."""

    DETECTOR_ID = "SOUL-BRIDGE-003"
    NAME = "Soul Atomic Swap Fund Loss"
    DESCRIPTION = "Detects HTLC atomic swap patterns that could lead to fund loss"
    SCWE_ID = "SOUL-041"
    CWE_ID = "CWE-400"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-bridge"
    CONFIDENCE = 0.80

    _SWAP_INIT = re.compile(r"(initiateSwap|createSwap|newSwap)", re.IGNORECASE)
    _SWAP_COMPLETE = re.compile(r"(completeSwap|claimSwap|redeemSwap)", re.IGNORECASE)
    _SWAP_REFUND = re.compile(r"(refundSwap|cancelSwap|reclaimSwap)", re.IGNORECASE)
    _TIMELOCK_CHECK = re.compile(r"(block\.timestamp.*timelock|timelock.*block\.timestamp|expired)", re.IGNORECASE)
    _HASHLOCK_CHECK = re.compile(r"(keccak256.*preimage|sha256.*preimage|hashlock|secretHash)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines
        has_init = has_complete = has_refund = False

        for i, line in enumerate(lines):
            if self._SWAP_INIT.search(line) and "function" in line:
                has_init = True
            if self._SWAP_COMPLETE.search(line) and "function" in line:
                has_complete = True
                body = "\n".join(lines[i:min(i + 25, len(lines))])

                if not self._HASHLOCK_CHECK.search(body):
                    findings.append(self._make_finding(
                        title="Swap completion lacks hashlock verification",
                        description=(
                            f"Swap completion at line {i + 1} does not verify the "
                            f"preimage against the hashlock. Anyone could complete "
                            f"the swap without knowing the secret."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        remediation=(
                            "Verify preimage: "
                            "`require(keccak256(abi.encodePacked(preimage)) == swap.hashlock)`"
                        ),
                    ))

            if self._SWAP_REFUND.search(line) and "function" in line:
                has_refund = True
                body = "\n".join(lines[i:min(i + 20, len(lines))])

                if not self._TIMELOCK_CHECK.search(body):
                    findings.append(self._make_finding(
                        title="Swap refund lacks timelock check",
                        description=(
                            f"Swap refund at line {i + 1} does not check if the timelock "
                            f"has expired. Premature refunds could lead to both parties "
                            f"getting funds (initiator refunds + counterparty claims)."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Check timelock: "
                            "`require(block.timestamp >= swap.timelock, \"Not yet expired\")`"
                        ),
                    ))

        # Check for missing refund mechanism
        if has_init and has_complete and not has_refund:
            findings.append(self._make_finding(
                title="Atomic swap missing refund mechanism",
                description=(
                    "The atomic swap contract has initiate and complete functions "
                    "but no refund/cancel mechanism. If the counterparty never "
                    "completes the swap, funds are permanently locked."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                severity=Severity.CRITICAL,
                remediation=(
                    "Add a refund function with timelock: "
                    "`function refundSwap(bytes32 swapId) external { "
                    "require(block.timestamp >= swap.timelock); "
                    "/* return funds to initiator */ }`"
                ),
            ))

        return findings


class CrossChainChainIdValidationDetector(BaseDetector):
    """Detect missing chain ID validation in cross-chain operations."""

    DETECTOR_ID = "SOUL-BRIDGE-004"
    NAME = "Soul Cross-Chain ID Validation"
    DESCRIPTION = "Detects cross-chain operations without proper chain ID validation"
    SCWE_ID = "SOUL-043"
    CWE_ID = "CWE-20"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-bridge"
    CONFIDENCE = 0.80

    _CROSS_CHAIN = re.compile(
        r"(destChainId|targetChain|sourceChain|remoteChain)",
        re.IGNORECASE,
    )
    _CHAIN_VALIDATE = re.compile(
        r"(supportedChains|isValidChain|chainWhitelist|require.*chainId|allowedChains)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._CROSS_CHAIN.search(line) and "function" in line:
                body = "\n".join(lines[i:min(i + 20, len(lines))])

                if not self._CHAIN_VALIDATE.search(body):
                    findings.append(self._make_finding(
                        title="Cross-chain operation lacks chain ID validation",
                        description=(
                            f"Cross-chain function at line {i + 1} accepts a destination "
                            f"chain ID parameter without validating it against a whitelist "
                            f"of supported chains. Sending to an unsupported chain would "
                            f"result in permanent fund loss."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Validate chain ID: "
                            "`require(supportedChains[destChainId], \"Unsupported chain\")` "
                            "with a governance-controlled whitelist."
                        ),
                    ))

        return findings


class BridgeRateLimitBypassDetector(BaseDetector):
    """Detect potential rate limiter bypass in bridge operations."""

    DETECTOR_ID = "SOUL-BRIDGE-005"
    NAME = "Soul Bridge Rate Limit Bypass"
    DESCRIPTION = "Detects patterns that could bypass bridge rate limiting"
    SCWE_ID = "SOUL-044"
    CWE_ID = "CWE-770"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-bridge"
    CONFIDENCE = 0.70

    _RATE_LIMIT = re.compile(
        r"(rateLimiter|_checkRate|rateLimit|BridgeRateLimiter)",
        re.IGNORECASE,
    )
    _BRIDGE_TRANSFER = re.compile(
        r"function\s+\w*(transfer|bridge|relay|send)\w*\s*\(.*\)\s*(external|public)",
        re.IGNORECASE,
    )
    _SPLIT_PATTERN = re.compile(
        r"(for\s*\(|batch|multiple|array|uint256\[\])",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        has_rate_limit = bool(self._RATE_LIMIT.search(context.source_code))

        if not has_rate_limit:
            for i, line in enumerate(lines):
                if self._BRIDGE_TRANSFER.search(line):
                    findings.append(self._make_finding(
                        title="Bridge transfer function lacks rate limiting",
                        description=(
                            f"Bridge transfer at line {i + 1} does not implement "
                            f"rate limiting. Without rate limits, an attacker could "
                            f"drain bridge funds rapidly or DoS the bridge."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                        remediation=(
                            "Integrate BridgeRateLimiter: "
                            "`modifier rateLimited(uint256 amount) { "
                            "rateLimiter.checkAndRecord(amount); _; }`"
                        ),
                    ))

        return findings

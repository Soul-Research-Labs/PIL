"""Soul Protocol ZK proof vulnerability detectors.

Detects:
  - Invalid proof acceptance
  - Proof replay across chains
  - Verifier registry manipulation
  - Proof translation integrity issues
  - Missing proof verification in state transitions
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class ProofVerificationBypassDetector(BaseDetector):
    """Detect state transitions without proper ZK proof verification."""

    DETECTOR_ID = "SOUL-ZK-001"
    NAME = "Soul ZK Proof Verification Bypass"
    DESCRIPTION = "Detects state-changing operations that lack ZK proof verification"
    SCWE_ID = "SOUL-010"
    CWE_ID = "CWE-287"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-zk-proof"
    CONFIDENCE = 0.85

    _STATE_CHANGE = re.compile(
        r"(unlock|update|transfer|withdraw|claim|complete|execute)\w*\s*\(",
        re.IGNORECASE,
    )
    _PROOF_VERIFY = re.compile(
        r"(verifyProof|verify\(|_verify|isValidProof|verifier\.|IVerifier)",
        re.IGNORECASE,
    )
    _REQUIRE_VERIFY = re.compile(
        r"require\(.*verify|assert\(.*verify|if.*!.*verify.*revert",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        # Identify if this is a Soul contract that should require proofs
        soul_indicators = [
            "ZKBoundStateLock", "ShieldedPool", "ProofCarryingContainer",
            "ConfidentialState", "StateLock", "ProofHub",
        ]
        is_soul_zk_contract = any(
            ind in context.source_code for ind in soul_indicators
        )

        if not is_soul_zk_contract:
            return findings

        # Find functions with state changes
        in_function = False
        func_start = 0
        func_name = ""
        func_body_lines: list[str] = []
        brace_depth = 0

        for i, line in enumerate(lines):
            func_match = re.match(
                r"\s*function\s+(\w+)\s*\(.*\)\s*(external|public)",
                line,
            )
            if func_match:
                in_function = True
                func_start = i
                func_name = func_match.group(1)
                func_body_lines = []
                brace_depth = 0

            if in_function:
                func_body_lines.append(line)
                brace_depth += line.count("{") - line.count("}")

                if brace_depth <= 0 and "{" in "\n".join(func_body_lines):
                    # End of function
                    func_body = "\n".join(func_body_lines)

                    if self._STATE_CHANGE.search(func_name):
                        has_verify = bool(self._PROOF_VERIFY.search(func_body))
                        has_require_verify = bool(self._REQUIRE_VERIFY.search(func_body))

                        if not has_verify and not has_require_verify:
                            # Check if it has proof parameter
                            has_proof_param = "proof" in func_body_lines[0].lower()

                            if has_proof_param:
                                findings.append(self._make_finding(
                                    title=f"Missing proof verification in {func_name}",
                                    description=(
                                        f"Function `{func_name}` at line {func_start + 1} accepts "
                                        f"a proof parameter but does not verify it. In Soul Protocol, "
                                        f"all state transitions involving ZK proofs must call "
                                        f"verifyProof() and revert on failure. Missing verification "
                                        f"allows arbitrary state changes with invalid proofs."
                                    ),
                                    file_path=context.contract_name + ".sol",
                                    start_line=func_start + 1,
                                    end_line=i + 1,
                                    snippet=func_body_lines[0].strip(),
                                    remediation=(
                                        "Add proof verification: "
                                        "`require(verifier.verifyProof(proof, publicInputs), "
                                        "\"Invalid proof\")` before any state changes."
                                    ),
                                ))

                    in_function = False

        return findings


class ProofReplayDetector(BaseDetector):
    """Detect missing proof replay protection across chains."""

    DETECTOR_ID = "SOUL-ZK-002"
    NAME = "Soul ZK Proof Replay"
    DESCRIPTION = "Detects proof acceptance patterns vulnerable to cross-chain replay"
    SCWE_ID = "SOUL-011"
    CWE_ID = "CWE-294"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-zk-proof"
    CONFIDENCE = 0.80

    _PROOF_SUBMIT = re.compile(
        r"(submitProof|relayProof|verifyAndExecute|processProof)",
        re.IGNORECASE,
    )
    _CHAIN_BINDING = re.compile(
        r"(block\.chainid|sourceChain|destChain|chainId|domain)",
        re.IGNORECASE,
    )
    _PROOF_HASH_CHECK = re.compile(
        r"(proofHash|usedProofs|processedProofs|proofNonce)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._PROOF_SUBMIT.search(line):
                # Check the function body for chain binding and replay check
                body = "\n".join(lines[i:min(i + 40, len(lines))])

                has_chain_binding = bool(self._CHAIN_BINDING.search(body))
                has_replay_check = bool(self._PROOF_HASH_CHECK.search(body))

                if not has_replay_check:
                    findings.append(self._make_finding(
                        title="Proof submission lacks replay protection",
                        description=(
                            f"The proof submission function at line {i + 1} does not "
                            f"track processed proofs. A valid proof could be submitted "
                            f"multiple times, or replayed from another chain. This is "
                            f"critical in cross-chain ZK bridges where proof uniqueness "
                            f"must be enforced alongside nullifier uniqueness."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Track proof hashes: `mapping(bytes32 => bool) processedProofs`. "
                            "On submission: `bytes32 hash = keccak256(proof); "
                            "require(!processedProofs[hash]); processedProofs[hash] = true;`. "
                            "Also bind proofs to source chain ID."
                        ),
                    ))

                if not has_chain_binding:
                    findings.append(self._make_finding(
                        title="Proof not bound to source chain",
                        description=(
                            f"Proof submission at line {i + 1} does not bind the proof "
                            f"to a specific chain. A proof valid on Chain A could be "
                            f"replayed on Chain B if the verifier accepts it. In Soul's "
                            f"cross-chain architecture, proofs must include source chain "
                            f"binding in public inputs."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        severity=Severity.HIGH,
                        remediation=(
                            "Include block.chainid in proof public inputs: "
                            "`require(publicInputs[0] == block.chainid)` and verify "
                            "the proof was generated for this specific chain."
                        ),
                    ))

        return findings


class VerifierRegistryManipulationDetector(BaseDetector):
    """Detect verifier registry manipulation vulnerabilities."""

    DETECTOR_ID = "SOUL-ZK-003"
    NAME = "Soul Verifier Registry Manipulation"
    DESCRIPTION = "Detects insufficient access control on verifier registry operations"
    SCWE_ID = "SOUL-012"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-zk-proof"
    CONFIDENCE = 0.80

    _VERIFIER_SET = re.compile(
        r"(setVerifier|registerVerifier|updateVerifier|addCircuit|removeCircuit)",
        re.IGNORECASE,
    )
    _ACCESS_CONTROL = re.compile(
        r"(onlyOwner|onlyAdmin|onlyGovernance|require.*msg\.sender|_checkRole)",
        re.IGNORECASE,
    )
    _TIMELOCK = re.compile(r"(timelock|TimelockController|delay|cooldown)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._VERIFIER_SET.search(line):
                func_body = "\n".join(lines[i:min(i + 15, len(lines))])

                has_access = bool(self._ACCESS_CONTROL.search(func_body))
                has_timelock = bool(self._TIMELOCK.search(context.source_code))

                if not has_access:
                    findings.append(self._make_finding(
                        title="Verifier registry modification without access control",
                        description=(
                            f"The verifier registry modification at line {i + 1} lacks "
                            f"access control. If anyone can register/update verifiers, "
                            f"an attacker could point the registry to a malicious verifier "
                            f"that accepts all proofs, bypassing all ZK security."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Add `onlyAdmin` or governance modifier. Verifier changes "
                            "should require timelock + multi-sig approval: "
                            "`function setVerifier(...) external onlyAdmin timelocked {...}`"
                        ),
                    ))
                elif not has_timelock:
                    findings.append(self._make_finding(
                        title="Verifier registry change lacks timelock",
                        description=(
                            f"Verifier registry is access-controlled but lacks timelock "
                            f"at line {i + 1}. A compromised admin key could instantly "
                            f"replace the verifier, leaving no time for users to exit. "
                            f"Soul Protocol requires timelock on all verifier changes."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        severity=Severity.HIGH,
                        remediation=(
                            "Use SoulUpgradeTimelock for verifier changes: "
                            "`require(block.timestamp >= changeTimestamp + TIMELOCK_DELAY)`"
                        ),
                    ))

        return findings


class ProofTranslationIntegrityDetector(BaseDetector):
    """Detect proof translation integrity issues (EASC)."""

    DETECTOR_ID = "SOUL-ZK-004"
    NAME = "Soul Proof Translation Integrity"
    DESCRIPTION = "Detects proof translation between backends without integrity verification"
    SCWE_ID = "SOUL-013"
    CWE_ID = "CWE-345"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-zk-proof"
    CONFIDENCE = 0.75

    _TRANSLATE = re.compile(
        r"(translate|convert|transform).*[Pp]roof",
        re.IGNORECASE,
    )
    _BACKEND = re.compile(
        r"(Groth16|PLONK|STARK|UltraPlonk|Bulletproof|proofBackend)",
        re.IGNORECASE,
    )
    _VERIFY_AFTER = re.compile(
        r"(verify.*after|post.*verify|_validateTranslation|require.*verify)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._TRANSLATE.search(line):
                body = "\n".join(lines[i:min(i + 20, len(lines))])

                has_post_verify = bool(self._VERIFY_AFTER.search(body))

                if not has_post_verify:
                    findings.append(self._make_finding(
                        title="Proof translation without post-verification",
                        description=(
                            f"Proof translation at line {i + 1} does not verify the "
                            f"translated proof in the target backend. When converting "
                            f"between proof systems (e.g., PLONK → Groth16), the "
                            f"translated proof must be verified to ensure correctness. "
                            f"Without this, corrupted translations could accept invalid state."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        remediation=(
                            "Verify translated proof in target backend: "
                            "`bytes memory translated = translator.translate(proof, targetBackend); "
                            "require(targetVerifier.verify(translated, publicInputs), "
                            "\"Translation verification failed\");`"
                        ),
                    ))

        return findings


class MissingProofExpirationDetector(BaseDetector):
    """Detect missing proof expiration for time-sensitive operations."""

    DETECTOR_ID = "SOUL-ZK-005"
    NAME = "Soul ZK Proof Expiration"
    DESCRIPTION = "Detects proof acceptance without timestamp/expiration checks"
    SCWE_ID = "SOUL-014"
    CWE_ID = "CWE-613"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "soul-zk-proof"
    CONFIDENCE = 0.70

    _PROOF_ACCEPT = re.compile(
        r"(verifyProof|submitProof|unlockWithProof|processProof)",
        re.IGNORECASE,
    )
    _TIMESTAMP_CHECK = re.compile(
        r"(block\.timestamp|deadline|expiry|validUntil|timeout)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._PROOF_ACCEPT.search(line):
                body = "\n".join(lines[i:min(i + 25, len(lines))])

                has_timestamp = bool(self._TIMESTAMP_CHECK.search(body))

                if not has_timestamp:
                    findings.append(self._make_finding(
                        title="Proof accepted without expiration check",
                        description=(
                            f"Proof acceptance at line {i + 1} has no timestamp or "
                            f"expiration check. In cross-chain protocols, old proofs "
                            f"may reference stale state. An attacker could hold a proof "
                            f"and submit it after conditions change (e.g., after a "
                            f"governance update or emergency action)."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Add proof expiration: include a timestamp in public inputs "
                            "and require `block.timestamp <= proofTimestamp + MAX_PROOF_AGE`."
                        ),
                    ))

        return findings

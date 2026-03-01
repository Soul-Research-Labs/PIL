"""Soul Protocol nullifier vulnerability detectors.

Detects:
  - Nullifier replay (double-spend)
  - Missing domain separation in CDNA
  - Batch nullifier atomicity issues
  - Zero/empty nullifier usage
  - Nullifier front-running
"""

from __future__ import annotations

import re
from typing import Any

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class NullifierReplayDetector(BaseDetector):
    """Detect missing nullifier-replay protection (double-spend)."""

    DETECTOR_ID = "SOUL-NULL-001"
    NAME = "Soul Nullifier Replay"
    DESCRIPTION = "Detects missing nullifier uniqueness checks that could enable double-spend"
    SCWE_ID = "SOUL-001"
    CWE_ID = "CWE-672"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-nullifier"
    CONFIDENCE = 0.85

    _NULLIFIER_REGISTER = re.compile(
        r"(registerNullifier|_registerNullifier|_recordNullifier|_markUsed)",
        re.IGNORECASE,
    )
    _NULLIFIER_CHECK = re.compile(
        r"(isNullifierUsed|nullifiers\[|_isUsed|_nullifierUsed|require.*nullifier)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            # Find nullifier registration
            if self._NULLIFIER_REGISTER.search(line):
                # Look backwards for a check
                check_found = False
                for j in range(max(0, i - 20), i):
                    if self._NULLIFIER_CHECK.search(lines[j]):
                        check_found = True
                        break

                if not check_found:
                    findings.append(self._make_finding(
                        title="Nullifier registered without duplicate check",
                        description=(
                            f"Nullifier is registered at line {i + 1} without a prior "
                            f"check for whether it has already been used. This could "
                            f"allow double-spend attacks if the same nullifier can be "
                            f"submitted multiple times."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                        remediation=(
                            "Add `require(!isNullifierUsed(nullifier), \"Nullifier already used\")` "
                            "before registration. Use the NullifierRegistry pattern."
                        ),
                    ))

        return findings


class DomainSeparationDetector(BaseDetector):
    """Detect missing domain separation in cross-domain nullifiers (CDNA)."""

    DETECTOR_ID = "SOUL-NULL-002"
    NAME = "Soul CDNA Domain Separation"
    DESCRIPTION = "Detects missing or weak domain separation in cross-domain nullifier computation"
    SCWE_ID = "SOUL-002"
    CWE_ID = "CWE-330"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-nullifier"
    CONFIDENCE = 0.80

    _DOMAIN_HASH = re.compile(
        r"(keccak256|sha256|poseidon).*\(.*domain",
        re.IGNORECASE,
    )
    _NULLIFIER_COMPUTE = re.compile(
        r"(computeNullifier|_deriveNullifier|nullifier\s*=)",
        re.IGNORECASE,
    )
    _CHAIN_ID = re.compile(r"(block\.chainid|chainId|chain_id)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        # Check if this is a CDNA-related contract
        has_cdna = any(
            "CrossDomainNullifier" in line or "domainNullifier" in line.lower()
            for line in lines
        )

        if not has_cdna:
            return findings

        for i, line in enumerate(lines):
            if self._NULLIFIER_COMPUTE.search(line):
                # Check if domain is included in hash
                context_window = "\n".join(lines[max(0, i - 5):i + 10])
                has_domain = bool(self._DOMAIN_HASH.search(context_window))
                has_chain = bool(self._CHAIN_ID.search(context_window))

                if not has_domain and not has_chain:
                    findings.append(self._make_finding(
                        title="Nullifier computation lacks domain separation",
                        description=(
                            f"Nullifier computation at line {i + 1} does not include "
                            f"domain or chain ID in the hash. This allows cross-domain "
                            f"nullifier collision: the same nullifier could be used on "
                            f"different chains, breaking privacy and enabling replay attacks."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Include domain identifier in nullifier hash: "
                            "`bytes32 nullifier = keccak256(abi.encode(secret, domain))`. "
                            "Use CDNA pattern: H(secret || CHAIN_ID) for each chain."
                        ),
                    ))

        return findings


class BatchNullifierAtomicityDetector(BaseDetector):
    """Detect non-atomic batch nullifier registration."""

    DETECTOR_ID = "SOUL-NULL-003"
    NAME = "Soul Batch Nullifier Atomicity"
    DESCRIPTION = "Detects non-atomic batch nullifier registration that could leave partial state"
    SCWE_ID = "SOUL-003"
    CWE_ID = "CWE-362"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-nullifier"
    CONFIDENCE = 0.75

    _BATCH_REGISTER = re.compile(
        r"(batchRegister|registerBatch|_batchRegister)",
        re.IGNORECASE,
    )
    _FOR_LOOP = re.compile(r"for\s*\(")
    _REQUIRE_IN_LOOP = re.compile(r"require\(|revert\b|assert\(")

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._BATCH_REGISTER.search(line):
                # Look for the for-loop body
                for j in range(i, min(i + 30, len(lines))):
                    if self._FOR_LOOP.search(lines[j]):
                        # Check if there's a pre-validation pass before the loop
                        pre_validation = False
                        for k in range(i, j):
                            if "validate" in lines[k].lower() or self._REQUIRE_IN_LOOP.search(lines[k]):
                                pre_validation = True
                                break

                        if not pre_validation:
                            findings.append(self._make_finding(
                                title="Batch nullifier registration may not be atomic",
                                description=(
                                    f"Batch nullifier registration at line {i + 1} uses a loop "
                                    f"without pre-validating all nullifiers. If one nullifier "
                                    f"in the batch is already used, the revert will waste gas "
                                    f"but more critically, partial state changes before the "
                                    f"failing element may not be properly rolled back."
                                ),
                                file_path=context.contract_name + ".sol",
                                start_line=i + 1,
                                end_line=j + 5,
                                snippet=line.strip(),
                                remediation=(
                                    "Pre-validate all nullifiers before registering any: "
                                    "1) Loop to check all are unused, 2) Loop to register all. "
                                    "Or use a try/catch pattern with rollback."
                                ),
                            ))
                        break

        return findings


class NullifierFrontRunDetector(BaseDetector):
    """Detect nullifier front-running vulnerability."""

    DETECTOR_ID = "SOUL-NULL-004"
    NAME = "Soul Nullifier Front-Running"
    DESCRIPTION = "Detects nullifier submission patterns vulnerable to front-running"
    SCWE_ID = "SOUL-004"
    CWE_ID = "CWE-362"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-nullifier"
    CONFIDENCE = 0.70

    _WITHDRAW = re.compile(r"function\s+withdraw", re.IGNORECASE)
    _COMMIT_REVEAL = re.compile(r"(commit|reveal|commitHash|deadline)", re.IGNORECASE)
    _MEV_PROTECT = re.compile(r"(MEVProtection|commitReveal|flashbots|privateTransaction)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        source = context.source_code

        # Check if withdrawal functions expose nullifier hash in mempool
        for i, line in enumerate(context.lines):
            if self._WITHDRAW.search(line):
                # Check if there's commit-reveal protection
                function_body = "\n".join(
                    context.lines[i:min(i + 50, len(context.lines))]
                )

                has_mev_protection = bool(self._MEV_PROTECT.search(source))
                has_commit_reveal = bool(self._COMMIT_REVEAL.search(function_body))

                if not has_mev_protection and not has_commit_reveal:
                    findings.append(self._make_finding(
                        title="Withdrawal lacks MEV/front-running protection",
                        description=(
                            f"The withdraw function at line {i + 1} exposes the nullifier "
                            f"hash in the transaction mempool. A front-runner could observe "
                            f"the pending withdrawal and either: extract the nullifier to "
                            f"block the withdrawal, or front-run with their own withdrawal "
                            f"using the same Merkle proof path."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                        remediation=(
                            "Implement commit-reveal scheme (MEVProtection.sol) or use "
                            "private mempool submission (Flashbots). The commit phase hides "
                            "the nullifier hash until it's safe to reveal."
                        ),
                    ))
                break

        return findings

"""Soul Protocol privacy and shielded pool vulnerability detectors.

Detects:
  - Shielded pool balance inflation/deflation
  - Merkle tree integrity violations
  - Stealth address metadata leakage
  - Encrypted state exposure
  - Privacy zone misconfiguration
  - View key authorization issues
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class ShieldedPoolInflationDetector(BaseDetector):
    """Detect shielded pool balance inflation/deflation vulnerabilities."""

    DETECTOR_ID = "SOUL-PRIV-001"
    NAME = "Soul Shielded Pool Inflation"
    DESCRIPTION = "Detects shielded pool deposit/withdraw patterns that could allow balance manipulation"
    SCWE_ID = "SOUL-050"
    CWE_ID = "CWE-682"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-privacy"
    CONFIDENCE = 0.85

    _DEPOSIT = re.compile(r"function\s+\w*deposit\w*\s*\(", re.IGNORECASE)
    _WITHDRAW = re.compile(r"function\s+\w*withdraw\w*\s*\(", re.IGNORECASE)
    _BALANCE_CHECK = re.compile(
        r"(totalDeposited|poolBalance|_balanceInvariant|require.*balance)",
        re.IGNORECASE,
    )
    _NULLIFIER_CHECK = re.compile(
        r"(nullifier|spent|usedNullifiers\[)",
        re.IGNORECASE,
    )
    _COMMITMENT_CHECK = re.compile(
        r"(commitment|commitments\[|merkleTree\.(insert|add)|_addLeaf)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        pool_indicators = [
            "ShieldedPool", "UniversalShieldedPool", "shielded",
            "privateDeposit", "privateWithdraw",
        ]
        is_pool = any(ind in context.source_code for ind in pool_indicators)
        if not is_pool:
            return findings

        for i, line in enumerate(lines):
            if self._DEPOSIT.search(line):
                body = "\n".join(lines[i:min(i + 30, len(lines))])

                if not self._COMMITMENT_CHECK.search(body):
                    findings.append(self._make_finding(
                        title="Deposit doesn't add commitment to Merkle tree",
                        description=(
                            f"Deposit function at line {i + 1} does not add a "
                            f"commitment to the Merkle tree. Without commitment "
                            f"insertion, the deposit receipt cannot be used for "
                            f"future withdrawals, locking funds permanently."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        remediation=(
                            "Insert commitment into Merkle tree: "
                            "`bytes32 commitment = hash(nullifier, amount, owner); "
                            "merkleTree.insert(commitment);`"
                        ),
                    ))

            if self._WITHDRAW.search(line):
                body = "\n".join(lines[i:min(i + 40, len(lines))])

                if not self._NULLIFIER_CHECK.search(body):
                    findings.append(self._make_finding(
                        title="Withdrawal doesn't check nullifier",
                        description=(
                            f"Withdraw function at line {i + 1} does not verify "
                            f"or mark the nullifier as spent. This enables double "
                            f"withdrawal — a CRITICAL shielded pool vulnerability "
                            f"that can drain all pool funds."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        remediation=(
                            "Check and mark nullifier: "
                            "`require(!spentNullifiers[nullifier], \"Already spent\"); "
                            "spentNullifiers[nullifier] = true;`"
                        ),
                    ))

                if not self._BALANCE_CHECK.search(body):
                    findings.append(self._make_finding(
                        title="Withdrawal lacks pool balance invariant check",
                        description=(
                            f"Withdraw function at line {i + 1} does not verify the "
                            f"pool balance invariant (total deposits >= total withdrawals). "
                            f"A bug in proof verification could allow withdrawing more "
                            f"than was deposited."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        severity=Severity.HIGH,
                        remediation=(
                            "Add balance invariant: "
                            "`require(address(this).balance >= amount || "
                            "IERC20(token).balanceOf(address(this)) >= amount);`"
                        ),
                    ))

        return findings


class MerkleTreeIntegrityDetector(BaseDetector):
    """Detect Merkle tree integrity violations in shielded pools."""

    DETECTOR_ID = "SOUL-PRIV-002"
    NAME = "Soul Merkle Tree Integrity"
    DESCRIPTION = "Detects Merkle tree operations that could break tree integrity"
    SCWE_ID = "SOUL-051"
    CWE_ID = "CWE-345"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-privacy"
    CONFIDENCE = 0.75

    _MERKLE_INSERT = re.compile(r"(insert|addLeaf|_insert|_hashPair)", re.IGNORECASE)
    _ROOT_UPDATE = re.compile(r"(roots\[|currentRoot|_updateRoot|latestRoot)", re.IGNORECASE)
    _HISTORY = re.compile(r"(rootHistory|knownRoots|isKnownRoot|ROOT_HISTORY)", re.IGNORECASE)
    _INDEX_CHECK = re.compile(r"(nextIndex|currentIndex|require.*index.*<.*levels)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        # Only check contracts with Merkle tree operations
        if not any(kw in context.source_code for kw in [
            "MerkleTree", "merkleTree", "merkle_tree", "IncrementalTree",
        ]):
            return findings

        has_history = bool(self._HISTORY.search(context.source_code))
        has_index = bool(self._INDEX_CHECK.search(context.source_code))

        if not has_history:
            findings.append(self._make_finding(
                title="Merkle tree lacks root history",
                description=(
                    "The contract uses a Merkle tree but does not maintain a "
                    "history of recent roots. Without root history, proofs "
                    "generated against a previous root become invalid the "
                    "moment a new leaf is inserted. This creates a race "
                    "condition where withdrawals fail if another deposit "
                    "occurs first."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                remediation=(
                    "Maintain root history: "
                    "`uint256 constant ROOT_HISTORY_SIZE = 30; "
                    "mapping(bytes32 => bool) public knownRoots; "
                    "function _updateRoot(bytes32 newRoot) internal { "
                    "knownRoots[newRoot] = true; }`"
                ),
            ))

        if not has_index:
            findings.append(self._make_finding(
                title="Merkle tree lacks index overflow protection",
                description=(
                    "The Merkle tree does not check the leaf index against "
                    "the maximum tree capacity (2^levels). If the tree "
                    "overflows, the hashing algorithm could produce "
                    "incorrect roots, breaking all commitment proofs."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                severity=Severity.MEDIUM,
                remediation=(
                    "Check tree capacity: "
                    "`require(nextIndex < 2**levels, \"Tree is full\")`"
                ),
            ))

        return findings


class StealthAddressLeakDetector(BaseDetector):
    """Detect stealth address metadata leakage patterns."""

    DETECTOR_ID = "SOUL-PRIV-003"
    NAME = "Soul Stealth Address Leak"
    DESCRIPTION = "Detects patterns that leak stealth address metadata"
    SCWE_ID = "SOUL-052"
    CWE_ID = "CWE-200"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-privacy"
    CONFIDENCE = 0.70

    _STEALTH = re.compile(r"(stealth|StealthAddress|generateStealth)", re.IGNORECASE)
    _EVENT_EMIT = re.compile(r"emit\s+\w+\s*\(", re.IGNORECASE)
    _ADDRESS_IN_EVENT = re.compile(
        r"emit\s+\w+\s*\([^)]*address\s+\w*recipient|emit\s+\w+\s*\([^)]*msg\.sender",
        re.IGNORECASE,
    )
    _ENCRYPTED_ANNOUNCE = re.compile(
        r"(encryptedAnnouncement|encryptedNote|ephemeralPub|sharedSecret)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        is_stealth = any(
            kw in context.source_code
            for kw in ["StealthAddress", "stealth", "StealthContractFactory"]
        )
        if not is_stealth:
            return findings

        for i, line in enumerate(lines):
            if self._EVENT_EMIT.search(line) and self._ADDRESS_IN_EVENT.search(line):
                findings.append(self._make_finding(
                    title="Event leaks stealth recipient address",
                    description=(
                        f"Event emission at line {i + 1} includes the recipient "
                        f"address in plaintext. In a stealth address protocol, "
                        f"the recipient should never be revealed on-chain. Only "
                        f"the ephemeral public key and encrypted announcement "
                        f"should be emitted."
                    ),
                    file_path=context.contract_name + ".sol",
                    start_line=i + 1,
                    end_line=i + 1,
                    snippet=line.strip(),
                    remediation=(
                        "Emit only encrypted data: "
                        "`emit StealthTransfer(ephemeralPubKey, encryptedNote)` "
                        "without revealing the stealth address."
                    ),
                ))

        if not self._ENCRYPTED_ANNOUNCE.search(context.source_code):
            findings.append(self._make_finding(
                title="Stealth protocol lacks encrypted announcements",
                description=(
                    "The stealth address contract does not use encrypted "
                    "announcements. Without encrypted ephemeral data, "
                    "third parties can link senders to stealth recipients "
                    "by brute-forcing the ephemeral key derivation."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                severity=Severity.MEDIUM,
                remediation=(
                    "Use encrypted announcements per ERC-5564: "
                    "`bytes encryptedAnnouncement = encrypt(ephemeralKey, viewTag);`"
                ),
            ))

        return findings


class EncryptedStateExposureDetector(BaseDetector):
    """Detect accidental exposure of encrypted/confidential state."""

    DETECTOR_ID = "SOUL-PRIV-004"
    NAME = "Soul Encrypted State Exposure"
    DESCRIPTION = "Detects patterns that could expose confidential state data"
    SCWE_ID = "SOUL-053"
    CWE_ID = "CWE-312"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-privacy"
    CONFIDENCE = 0.75

    _GET_STATE = re.compile(
        r"function\s+\w*(getState|getEncrypted|readState|fetchState)\w*\s*\(",
        re.IGNORECASE,
    )
    _PUBLIC_MAPPING = re.compile(
        r"mapping\s*\([^)]+\)\s+public\s+\w*(encrypted|confidential|private|secret|hidden)",
        re.IGNORECASE,
    )
    _VIEW_KEY_CHECK = re.compile(
        r"(viewKey|viewingKey|require.*viewKey|_checkViewPermission|authorized.*View)",
        re.IGNORECASE,
    )
    _RETURN_RAW = re.compile(
        r"return\s+(encryptedState|_state|confidentialData|secretData)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        # Check for public mappings of encrypted state
        for i, line in enumerate(lines):
            if self._PUBLIC_MAPPING.search(line):
                findings.append(self._make_finding(
                    title="Encrypted state stored in public mapping",
                    description=(
                        f"Line {i + 1}: Encrypted/confidential state is in a "
                        f"`public` mapping, making it readable by any external "
                        f"caller without view key authorization. While data is "
                        f"encrypted on-chain, the public getter bypasses the "
                        f"ConfidentialStateContainer's access control."
                    ),
                    file_path=context.contract_name + ".sol",
                    start_line=i + 1,
                    end_line=i + 1,
                    snippet=line.strip(),
                    remediation=(
                        "Make mapping internal and add view-key-gated getter: "
                        "`mapping(...) internal _encryptedState; "
                        "function getState(bytes32 viewKey) external view "
                        "returns (bytes memory) { _checkViewKey(viewKey); ... }`"
                    ),
                ))

        # Check state getters without view key authorization
        for i, line in enumerate(lines):
            if self._GET_STATE.search(line):
                body = "\n".join(lines[i:min(i + 15, len(lines))])

                if not self._VIEW_KEY_CHECK.search(body):
                    findings.append(self._make_finding(
                        title="State getter lacks view key authorization",
                        description=(
                            f"State access function at line {i + 1} does not "
                            f"check view key authorization. In Soul Protocol's "
                            f"privacy model, encrypted state should only be "
                            f"accessible to holders of valid view keys registered "
                            f"in the ViewKeyRegistry."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Gate with view key: "
                            "`require(viewKeyRegistry.isAuthorized(msg.sender, stateId))`"
                        ),
                    ))

        return findings


class PrivacyZoneMisconfigDetector(BaseDetector):
    """Detect privacy zone misconfiguration patterns."""

    DETECTOR_ID = "SOUL-PRIV-005"
    NAME = "Soul Privacy Zone Misconfig"
    DESCRIPTION = "Detects privacy zone configuration that could weaken privacy guarantees"
    SCWE_ID = "SOUL-054"
    CWE_ID = "CWE-16"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "soul-privacy"
    CONFIDENCE = 0.65

    _ZONE_CREATE = re.compile(r"(createZone|newPrivacyZone|registerZone)", re.IGNORECASE)
    _ANONYMITY_SET = re.compile(r"(anonymitySet|minAnonymitySet|privacySet|mixingSet)", re.IGNORECASE)
    _TIME_DELAY = re.compile(r"(timeDelay|mixingDelay|withdrawDelay|MIN_DELAY)", re.IGNORECASE)
    _DENOMINATION = re.compile(r"(denomination|fixedAmount|AMOUNT)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        if "PrivacyZone" not in context.source_code and \
           "privacyZone" not in context.source_code:
            return findings

        has_anonymity = bool(self._ANONYMITY_SET.search(context.source_code))
        has_delay = bool(self._TIME_DELAY.search(context.source_code))
        has_denomination = bool(self._DENOMINATION.search(context.source_code))

        if not has_anonymity:
            findings.append(self._make_finding(
                title="Privacy zone lacks anonymity set enforcement",
                description=(
                    "The privacy zone does not enforce a minimum anonymity set "
                    "size. Without this, a zone with very few participants "
                    "provides weak privacy — an observer could easily deduce "
                    "the sender-receiver linkage."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                remediation=(
                    "Enforce minimum anonymity set: "
                    "`require(zone.participants >= MIN_ANONYMITY_SET, "
                    "\"Insufficient privacy\");`"
                ),
            ))

        if not has_delay and not has_denomination:
            findings.append(self._make_finding(
                title="Privacy zone missing timing/amount protections",
                description=(
                    "The privacy zone does not enforce withdrawal delays or "
                    "fixed denominations. Without these, deposit-withdraw "
                    "timing correlation and unique-amount analysis can "
                    "deanonymize users."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                remediation=(
                    "Add timing and denomination constraints: "
                    "`require(block.timestamp >= deposit.time + MIN_DELAY); "
                    "require(amount == FIXED_DENOMINATION);`"
                ),
            ))

        return findings

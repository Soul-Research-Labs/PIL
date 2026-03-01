"""Soul Protocol access control and governance vulnerability detectors.

Detects:
  - Privilege escalation in SecurityModule
  - Emergency bypass abuse
  - Timelock circumvention
  - Missing multi-sig requirements
  - Kill switch abuse
  - Governance manipulation
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class PrivilegeEscalationDetector(BaseDetector):
    """Detect privilege escalation patterns in Soul security modules."""

    DETECTOR_ID = "SOUL-ACL-001"
    NAME = "Soul Privilege Escalation"
    DESCRIPTION = "Detects privilege escalation via role manipulation in Soul security modules"
    SCWE_ID = "SOUL-060"
    CWE_ID = "CWE-269"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "soul-access-control"
    CONFIDENCE = 0.80

    _GRANT_ROLE = re.compile(
        r"(grantRole|setRole|addAdmin|setOperator|_grantRole)",
        re.IGNORECASE,
    )
    _ROLE_CHECK = re.compile(
        r"(onlyRole|hasRole|require.*role|onlyOwner|onlyAdmin|onlyGovernance)",
        re.IGNORECASE,
    )
    _SELF_GRANT = re.compile(
        r"(grantRole\s*\([^)]*msg\.sender|_grantRole\s*\([^)]*msg\.sender)",
        re.IGNORECASE,
    )
    _TIMELOCK = re.compile(
        r"(timelock|TimelockController|delay|pendingAdmin|executeAfter)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._GRANT_ROLE.search(line) and "function" in line:
                body = "\n".join(lines[i:min(i + 20, len(lines))])

                if not self._ROLE_CHECK.search(body):
                    findings.append(self._make_finding(
                        title="Role grant function lacks access control",
                        description=(
                            f"Role granting function at line {i + 1} does not "
                            f"verify the caller has admin privileges. Any address "
                            f"could grant itself elevated roles, bypassing Soul "
                            f"Protocol's SecurityModule."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Add access control: "
                            "`function grantRole(bytes32 role, address account) "
                            "external onlyRole(DEFAULT_ADMIN_ROLE) { ... }`"
                        ),
                    ))

                if not self._TIMELOCK.search(body):
                    findings.append(self._make_finding(
                        title="Role change not timelocked",
                        description=(
                            f"Role change at line {i + 1} executes immediately "
                            f"without a timelock delay. Critical role changes "
                            f"should go through a timelock to give the community "
                            f"time to react to malicious governance actions."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Use timelock for role changes: "
                            "`TimelockController.schedule(grantRole.selector, delay)`"
                        ),
                    ))

            # Detect self-granting patterns
            if self._SELF_GRANT.search(line):
                findings.append(self._make_finding(
                    title="Self-role-grant pattern detected",
                    description=(
                        f"Line {i + 1} grants a role to msg.sender. This is a "
                        f"common privilege escalation pattern — if the function "
                        f"is externally callable, any address can elevate itself."
                    ),
                    file_path=context.contract_name + ".sol",
                    start_line=i + 1,
                    end_line=i + 1,
                    snippet=line.strip(),
                    remediation=(
                        "Never allow self-granting. Require a separate admin "
                        "to grant roles to other addresses."
                    ),
                ))

        return findings


class EmergencyBypassDetector(BaseDetector):
    """Detect emergency mechanism abuse vectors."""

    DETECTOR_ID = "SOUL-ACL-002"
    NAME = "Soul Emergency Bypass"
    DESCRIPTION = "Detects emergency functions that could be abused to bypass security"
    SCWE_ID = "SOUL-061"
    CWE_ID = "CWE-285"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-access-control"
    CONFIDENCE = 0.75

    _EMERGENCY = re.compile(
        r"function\s+\w*(emergency|panic|kill|nuke|abort)\w*\s*\(",
        re.IGNORECASE,
    )
    _MULTI_SIG = re.compile(
        r"(multiSig|multisig|gnosis|requiredSignatures|quorum|_checkSignatures)",
        re.IGNORECASE,
    )
    _COOLDOWN = re.compile(
        r"(cooldown|cooldownPeriod|lastEmergency|_checkCooldown|emergencyDelay)",
        re.IGNORECASE,
    )
    _FUND_SWEEP = re.compile(
        r"(transfer\s*\(|safeTransfer|call\{value|sendValue|sweep)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._EMERGENCY.search(line):
                body = "\n".join(lines[i:min(i + 30, len(lines))])

                if not self._MULTI_SIG.search(body) and not self._MULTI_SIG.search(context.source_code):
                    findings.append(self._make_finding(
                        title="Emergency function not multi-sig protected",
                        description=(
                            f"Emergency function at line {i + 1} can be triggered "
                            f"by a single address. In Soul Protocol, emergency "
                            f"actions (EmergencyRecovery, EnhancedKillSwitch) "
                            f"should require multi-sig approval to prevent a "
                            f"compromised key from disrupting the protocol."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Require multi-sig: "
                            "`require(emergencyMultisig.isConfirmed(proposalId))`"
                        ),
                    ))

                if self._FUND_SWEEP.search(body):
                    findings.append(self._make_finding(
                        title="Emergency function can sweep funds",
                        description=(
                            f"Emergency function at line {i + 1} can transfer "
                            f"funds. Combined with insufficient access control, "
                            f"this creates a rug-pull vector. Emergency fund "
                            f"recovery in Soul must route through a timelocked "
                            f"recovery contract."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 5,
                        snippet=line.strip(),
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Route emergency fund recovery through timelock: "
                            "`EmergencyRecovery.proposeRecovery() → 48h delay → "
                            "EmergencyRecovery.executeRecovery()`"
                        ),
                    ))

                if not self._COOLDOWN.search(body):
                    findings.append(self._make_finding(
                        title="Emergency function lacks cooldown",
                        description=(
                            f"Emergency function at line {i + 1} has no cooldown "
                            f"period. An attacker who gains emergency access "
                            f"could trigger it repeatedly, permanently disrupting "
                            f"the protocol."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 2,
                        snippet=line.strip(),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Add cooldown: "
                            "`require(block.timestamp >= lastEmergency + COOLDOWN);`"
                        ),
                    ))

        return findings


class KillSwitchAbuseDetector(BaseDetector):
    """Detect kill switch patterns that could be abused."""

    DETECTOR_ID = "SOUL-ACL-003"
    NAME = "Soul Kill Switch Abuse"
    DESCRIPTION = "Detects kill switch implementations vulnerable to abuse"
    SCWE_ID = "SOUL-062"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-access-control"
    CONFIDENCE = 0.70

    _KILL_SWITCH = re.compile(r"(killSwitch|pause|shutdown|freeze|halt)", re.IGNORECASE)
    _IRREVERSIBLE = re.compile(r"(selfdestruct|SELFDESTRUCT|suicide)", re.IGNORECASE)
    _RECOVERY = re.compile(r"(unpause|resume|recover|restart|revive)", re.IGNORECASE)
    _GRADUAL = re.compile(r"(gracePeriod|graduatedShutdown|phased|partialPause)", re.IGNORECASE)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        for i, line in enumerate(lines):
            if self._IRREVERSIBLE.search(line):
                findings.append(self._make_finding(
                    title="Irreversible contract destruction",
                    description=(
                        f"Line {i + 1} uses selfdestruct which irreversibly "
                        f"destroys the contract. Soul Protocol's EnhancedKillSwitch "
                        f"uses graduated shutdown — not destruction. A reversible "
                        f"pause mechanism is always preferred."
                    ),
                    file_path=context.contract_name + ".sol",
                    start_line=i + 1,
                    end_line=i + 1,
                    snippet=line.strip(),
                    severity=Severity.CRITICAL,
                    remediation=(
                        "Replace selfdestruct with pausable pattern: "
                        "`bool public paused; modifier whenNotPaused() { "
                        "require(!paused); _; }`"
                    ),
                ))

        has_kill = bool(self._KILL_SWITCH.search(context.source_code))
        has_recovery = bool(self._RECOVERY.search(context.source_code))

        if has_kill and not has_recovery:
            findings.append(self._make_finding(
                title="Kill switch without recovery mechanism",
                description=(
                    "The contract has a kill/pause mechanism but no "
                    "corresponding recovery/unpause function. Once "
                    "triggered, the contract would be permanently frozen. "
                    "Soul Protocol requires graduated, reversible shutdown."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                remediation=(
                    "Add recovery: `function unpause() external onlyMultisig { "
                    "require(block.timestamp >= pausedAt + GRACE_PERIOD); "
                    "paused = false; }`"
                ),
            ))

        return findings


class UpgradeSecurityDetector(BaseDetector):
    """Detect upgrade mechanism security issues."""

    DETECTOR_ID = "SOUL-ACL-004"
    NAME = "Soul Upgrade Security"
    DESCRIPTION = "Detects unsafe upgrade patterns in Soul Protocol contracts"
    SCWE_ID = "SOUL-063"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.HIGH
    CATEGORY = "soul-access-control"
    CONFIDENCE = 0.80

    _UPGRADE = re.compile(
        r"function\s+\w*(upgrade|updateImplementation|setImplementation)\w*\s*\(",
        re.IGNORECASE,
    )
    _STORAGE_GAP = re.compile(r"__gap|__reserved|storage.*gap", re.IGNORECASE)
    _INITIALIZER = re.compile(r"(initializer|reinitializer|onlyInitializing)", re.IGNORECASE)
    _UUPS = re.compile(r"(UUPSUpgradeable|_authorizeUpgrade|proxiableUUID)", re.IGNORECASE)
    _STORAGE_CHECK = re.compile(
        r"(_checkStorageLayout|storageSlot|ERC7201|namespaced|StorageSlot)",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        lines = context.lines

        is_upgradeable = bool(self._UUPS.search(context.source_code)) or \
                         "Upgradeable" in context.source_code or \
                         "proxy" in context.source_code.lower()

        if not is_upgradeable:
            return findings

        has_gap = bool(self._STORAGE_GAP.search(context.source_code))
        has_initializer = bool(self._INITIALIZER.search(context.source_code))
        has_storage_check = bool(self._STORAGE_CHECK.search(context.source_code))

        if not has_gap:
            findings.append(self._make_finding(
                title="Upgradeable contract missing storage gap",
                description=(
                    "The upgradeable contract does not include a storage gap. "
                    "Without `uint256[50] __gap;`, adding new state variables "
                    "in an upgrade would shift existing storage slots, "
                    "corrupting all persistent state."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                remediation=(
                    "Add storage gap: `uint256[50] private __gap;` at the "
                    "end of the contract, or use ERC-7201 namespaced storage."
                ),
            ))

        if not has_initializer:
            findings.append(self._make_finding(
                title="Upgradeable contract missing initializer guard",
                description=(
                    "The upgradeable contract does not use the initializer "
                    "modifier. Without it, the initialize function could be "
                    "called multiple times, allowing an attacker to "
                    "re-initialize the contract and take ownership."
                ),
                file_path=context.contract_name + ".sol",
                start_line=1,
                end_line=1,
                snippet="",
                severity=Severity.CRITICAL,
                remediation=(
                    "Use initializer modifier: "
                    "`function initialize() external initializer { ... }`"
                ),
            ))

        for i, line in enumerate(lines):
            if self._UPGRADE.search(line):
                body = "\n".join(lines[i:min(i + 15, len(lines))])

                timelock_check = re.search(
                    r"(timelock|delay|TimelockController|schedule)",
                    body, re.IGNORECASE,
                )
                if not timelock_check:
                    findings.append(self._make_finding(
                        title="Upgrade function not timelocked",
                        description=(
                            f"Upgrade function at line {i + 1} executes "
                            f"immediately without a timelock. Soul Protocol "
                            f"upgrades should have a minimum 48-hour delay "
                            f"for community review."
                        ),
                        file_path=context.contract_name + ".sol",
                        start_line=i + 1,
                        end_line=i + 3,
                        snippet=line.strip(),
                        remediation=(
                            "Timelock upgrades: "
                            "`function _authorizeUpgrade(address newImpl) "
                            "internal override { require(timelock.isReady(upgradeId)); }`"
                        ),
                    ))

        return findings

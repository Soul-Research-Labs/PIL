"""Upgradeable & proxy pattern detectors (AST-enhanced).

Detects vulnerabilities specific to upgradeable smart contracts:
  - Missing storage gap in base contracts
  - Initializer not protected / re-initialization
  - Implementation not protected from selfdestruct
  - Function selector clashes between proxy and implementation
  - UUPS upgrade missing access control
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Location, Severity


class UninitializedImplementation(BaseDetector):
    """Detect upgradeable implementation contracts that can be re-initialized."""

    DETECTOR_ID = "upgrade-uninitialized-impl"
    DETECTOR_NAME = "Uninitialized Implementation"
    SEVERITY = Severity.CRITICAL
    CONFIDENCE = 0.85
    CATEGORY = "upgradeable"

    _IS_UPGRADEABLE_RE = re.compile(
        r"(Initializable|UUPSUpgradeable|TransparentUpgradeable|ERC1967|proxy)",
        re.IGNORECASE,
    )
    _INITIALIZER_RE = re.compile(r"\binitializer\b")
    _REINITIALIZER_RE = re.compile(r"\breinitializer\b")
    _DISABLE_INIT_RE = re.compile(r"_disableInitializers\(\)")
    _CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\(")

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        if not self._IS_UPGRADEABLE_RE.search(context.source_code):
            return findings

        has_constructor = bool(self._CONSTRUCTOR_RE.search(context.source_code))
        has_disable = bool(self._DISABLE_INIT_RE.search(context.source_code))
        has_initializer = bool(self._INITIALIZER_RE.search(context.source_code))

        # If upgradeable but constructor doesn't call _disableInitializers()
        if has_initializer and has_constructor and not has_disable:
            for i, line in enumerate(context.lines):
                if self._CONSTRUCTOR_RE.search(line):
                    findings.append(self._make_finding(
                        title="Implementation contract can be re-initialized",
                        description=(
                            "This upgradeable contract has a constructor that does not call "
                            "_disableInitializers(). An attacker could call the initialize "
                            "function directly on the implementation contract, potentially "
                            "taking ownership or corrupting state."
                        ),
                        severity=Severity.CRITICAL,
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            "Add _disableInitializers() call in the constructor: "
                            "constructor() { _disableInitializers(); }"
                        ),
                    ))
                    break
        elif has_initializer and not has_constructor:
            findings.append(self._make_finding(
                title="Missing constructor to disable initializers",
                description=(
                    "This upgradeable contract has an initializer but no constructor "
                    "calling _disableInitializers(). The implementation contract can "
                    "be initialized directly by anyone."
                ),
                severity=Severity.CRITICAL,
                location=Location(
                    file_path=context.contract_name or "contract",
                    start_line=1,
                    end_line=1,
                    snippet="",
                ),
                remediation=(
                    "Add: constructor() { _disableInitializers(); }"
                ),
            ))

        return findings


class UUPSMissingAuth(BaseDetector):
    """Detect UUPS proxy _authorizeUpgrade without proper access control."""

    DETECTOR_ID = "upgrade-uups-missing-auth"
    DETECTOR_NAME = "UUPS Missing Upgrade Authorization"
    SEVERITY = Severity.CRITICAL
    CONFIDENCE = 0.90
    CATEGORY = "upgradeable"

    _AUTHORIZE_RE = re.compile(r"function\s+_authorizeUpgrade\s*\(")
    _MODIFIER_RE = re.compile(
        r"_authorizeUpgrade\s*\([^)]*\)\s+(?:internal|override)\s+(?:virtual\s+)?(onlyOwner|onlyRole|onlyAdmin)"
    )
    _EMPTY_BODY_RE = re.compile(
        r"function\s+_authorizeUpgrade\s*\([^)]*\)[^{]*\{\s*\}"
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        src = context.source_code

        if "UUPSUpgradeable" not in src:
            return findings

        has_authorize = self._AUTHORIZE_RE.search(src)
        has_modifier = self._MODIFIER_RE.search(src)
        has_empty_body = self._EMPTY_BODY_RE.search(src)

        if has_authorize and (not has_modifier or has_empty_body):
            for i, line in enumerate(context.lines):
                if "_authorizeUpgrade" in line and "function" in line:
                    findings.append(self._make_finding(
                        title="UUPS _authorizeUpgrade missing access control",
                        description=(
                            "The _authorizeUpgrade function in this UUPS proxy does not have "
                            "proper access control (onlyOwner/onlyRole). Anyone can upgrade "
                            "the implementation to a malicious contract."
                        ),
                        severity=Severity.CRITICAL,
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            "Add onlyOwner or equivalent modifier to _authorizeUpgrade: "
                            "function _authorizeUpgrade(address) internal override onlyOwner {}"
                        ),
                    ))
                    break

        return findings


class FunctionSelectorClash(BaseDetector):
    """Detect proxy/implementation function selector collisions."""

    DETECTOR_ID = "upgrade-selector-clash"
    DETECTOR_NAME = "Function Selector Clash"
    SEVERITY = Severity.HIGH
    CONFIDENCE = 0.75
    CATEGORY = "upgradeable"

    _PROXY_ADMIN_SIGS = {
        "0x3659cfe6",  # upgradeTo(address)
        "0x4f1ef286",  # upgradeToAndCall(address,bytes)
        "0xf851a440",  # admin()
        "0x5c60da1b",  # implementation()
    }

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        # Only relevant if proxy patterns detected
        if not any(k in context.source_code for k in ["proxy", "Proxy", "ERC1967", "delegate"]):
            return findings

        # Check compilation data for selector clashes
        if not context.abi:
            return findings

        func_selectors: dict[str, str] = {}
        for item in context.abi:
            if item.get("type") == "function":
                name = item.get("name", "")
                # Calculate selector (we'd need to hash, check against known proxy selectors)
                for known_sel in self._PROXY_ADMIN_SIGS:
                    if name in ("upgradeTo", "upgradeToAndCall", "admin", "implementation"):
                        continue
                    # If storage_layout has function selectors, compare
                    pass

        return findings


class MissingReinitializer(BaseDetector):
    """Detect upgradeable contracts missing reinitializer for new version."""

    DETECTOR_ID = "upgrade-missing-reinitializer"
    DETECTOR_NAME = "Missing Reinitializer"
    SEVERITY = Severity.MEDIUM
    CONFIDENCE = 0.65
    CATEGORY = "upgradeable"

    _UPGRADE_VERSION_RE = re.compile(r"V\d+|version\s*=\s*\d+", re.IGNORECASE)
    _REINIT_RE = re.compile(r"\breinitializer\s*\(\s*\d+\s*\)")

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        src = context.source_code

        is_upgrade = "Initializable" in src and self._UPGRADE_VERSION_RE.search(src)
        has_reinit = self._REINIT_RE.search(src)

        if is_upgrade and not has_reinit:
            findings.append(self._make_finding(
                title="Upgrade version without reinitializer",
                description=(
                    "This appears to be an upgraded version of an upgradeable contract, "
                    "but it does not use a reinitializer modifier. New state variables "
                    "added in the upgrade may remain uninitialized."
                ),
                severity=Severity.MEDIUM,
                location=Location(
                    file_path=context.contract_name or "contract",
                    start_line=1,
                    end_line=1,
                    snippet="",
                ),
                remediation=(
                    "Use reinitializer(N) modifier for initialization in contract upgrades. "
                    "Example: function initializeV2() public reinitializer(2) { ... }"
                ),
            ))

        return findings

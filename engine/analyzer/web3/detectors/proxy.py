"""Proxy and upgradeability vulnerability detectors — SCWE-005, SCWE-036."""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class UninitializedProxyDetector(BaseDetector):
    """Detect uninitialized proxy implementation contracts."""

    DETECTOR_ID = "SCWE-005-001"
    NAME = "Uninitialized Proxy Implementation"
    DESCRIPTION = "Implementation contract may be uninitialized, allowing takeover"
    SCWE_ID = "SCWE-005"
    CWE_ID = "CWE-665"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "proxy"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code

        # Check if it's an upgradeable contract
        is_upgradeable = any(kw in source for kw in [
            "Initializable", "initializer", "initialize(", "UUPSUpgradeable",
            "TransparentUpgradeableProxy", "ERC1967"
        ])

        if not is_upgradeable:
            return findings

        # Check for constructor that calls _disableInitializers
        has_disable = "_disableInitializers()" in source
        has_constructor = re.search(r"constructor\s*\(", source) is not None

        if not has_disable:
            lines = source.split("\n")
            for i, line in enumerate(lines, 1):
                if "contract " in line and ("Initializable" in source or "initializer" in source):
                    findings.append(self._make_finding(
                        title="Implementation contract lacks _disableInitializers()",
                        description=(
                            "The implementation contract does not call `_disableInitializers()` in its constructor. "
                            "An attacker can call `initialize()` on the implementation contract directly "
                            "and potentially take ownership or manipulate state."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i,
                        end_line=i,
                        snippet=line.strip(),
                        remediation=(
                            "Add a constructor that calls `_disableInitializers()`:\n"
                            "```solidity\nconstructor() {\n    _disableInitializers();\n}\n```"
                        ),
                    ))
                    break
        return findings


class StorageCollisionDetector(BaseDetector):
    """Detect potential storage slot collisions in proxy patterns."""

    DETECTOR_ID = "SCWE-005-002"
    NAME = "Proxy Storage Collision"
    DESCRIPTION = "Storage layout collision risk between proxy and implementation"
    SCWE_ID = "SCWE-005"
    CWE_ID = "CWE-665"
    SEVERITY = Severity.HIGH
    CATEGORY = "proxy"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Detect manual proxy patterns without EIP-1967
        has_proxy_pattern = "delegatecall" in source and "fallback()" in source
        uses_eip1967 = any(kw in source for kw in [
            "ERC1967", "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "StorageSlot", "_IMPLEMENTATION_SLOT"
        ])

        if has_proxy_pattern and not uses_eip1967:
            for i, line in enumerate(lines, 1):
                if "delegatecall" in line:
                    findings.append(self._make_finding(
                        title="Proxy may have storage slot collisions",
                        description=(
                            "This proxy contract uses delegatecall but does not appear to use "
                            "EIP-1967 standard storage slots. Storage variables in the proxy "
                            "may collide with the implementation's storage layout."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i,
                        end_line=i,
                        snippet=line.strip(),
                        remediation="Use EIP-1967 standard storage slots or OpenZeppelin's proxy contracts.",
                    ))
                    break
        return findings


class FunctionClashingDetector(BaseDetector):
    """Detect selector clashing in proxy contracts."""

    DETECTOR_ID = "SCWE-036-001"
    NAME = "Proxy Function Selector Clash"
    DESCRIPTION = "Proxy admin functions may clash with implementation selectors"
    SCWE_ID = "SCWE-036"
    CWE_ID = "CWE-436"
    SEVERITY = Severity.HIGH
    CATEGORY = "proxy"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code

        # Detect transparent proxy pattern without proper selector isolation
        has_admin_functions = any(kw in source for kw in [
            "upgradeTo(", "upgradeToAndCall(", "changeAdmin(", "admin()"
        ])
        has_delegatecall = "delegatecall" in source

        if has_admin_functions and has_delegatecall:
            if "TransparentUpgradeableProxy" not in source and "ifAdmin" not in source:
                lines = source.split("\n")
                for i, line in enumerate(lines, 1):
                    if any(fn in line for fn in ["upgradeTo(", "changeAdmin("]):
                        findings.append(self._make_finding(
                            title="Proxy admin functions may clash with implementation selectors",
                            description=(
                                "Admin functions like `upgradeTo()` are defined alongside delegatecall. "
                                "Without proper selector isolation (like Transparent Proxy's `ifAdmin` modifier), "
                                "a function in the implementation with the same 4-byte selector could be shadowed."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i,
                            end_line=i,
                            snippet=line.strip(),
                            remediation="Use OpenZeppelin's TransparentUpgradeableProxy or UUPS pattern for proper selector isolation.",
                        ))
                        break
        return findings


class MissingUpgradeAuthDetector(BaseDetector):
    """Detect UUPS proxies without _authorizeUpgrade protection."""

    DETECTOR_ID = "SCWE-005-003"
    NAME = "Missing Upgrade Authorization"
    DESCRIPTION = "UUPS proxy without proper _authorizeUpgrade guard"
    SCWE_ID = "SCWE-005"
    CWE_ID = "CWE-862"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "proxy"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        if "UUPSUpgradeable" not in source:
            return findings

        # Check _authorizeUpgrade has access control
        auth_pattern = re.search(
            r"function\s+_authorizeUpgrade\s*\([^)]*\)[^{]*\{([^}]*)\}",
            source, re.DOTALL
        )

        if auth_pattern:
            body = auth_pattern.group(1).strip()
            # Empty body or no access control
            if not body or not any(kw in body for kw in [
                "onlyOwner", "require(", "onlyRole", "msg.sender", "_checkOwner"
            ]):
                line_offset = source[:auth_pattern.start()].count("\n") + 1
                findings.append(self._make_finding(
                    title="_authorizeUpgrade has no access control",
                    description=(
                        "The `_authorizeUpgrade` function in this UUPS proxy does not enforce "
                        "access control. Anyone can upgrade the implementation, allowing "
                        "an attacker to point it to a malicious contract."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_offset,
                    end_line=line_offset,
                    snippet=auth_pattern.group(0)[:100],
                    remediation="Add `onlyOwner` or `onlyRole(UPGRADER_ROLE)` modifier to `_authorizeUpgrade`.",
                ))
        return findings

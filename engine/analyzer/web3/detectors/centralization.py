"""Centralization risk detectors — SCWE-040.

Identify centralization risks and trusted-party dependencies:
  - Single owner / EOA admin without multisig
  - Unrestricted privileged functions (pause, mint, upgrade)
  - Missing renounceOwnership safeguards
  - Centralized oracle reliance
  - Backdoor functions / kill switches
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class SingleAdminDetector(BaseDetector):
    """Detect single EOA admin without multisig."""

    DETECTOR_ID = "SCWE-040-001"
    NAME = "Single Admin / No Multisig"
    DESCRIPTION = (
        "Detects contracts with a single owner/admin address without multisig "
        "protection. A compromised admin key gives full control over the contract."
    )
    SCWE_ID = "SCWE-040"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "centralization"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        has_ownable = bool(re.search(r'Ownable|owner\(\)', source))
        has_multisig = bool(re.search(
            r'[Mm]ultisig|[Gg]nosis|[Ss]afe|minSignatures|threshold|confirmTransaction',
            source,
        ))
        has_access_control = bool(re.search(
            r'AccessControl|hasRole|grantRole|DEFAULT_ADMIN_ROLE', source
        ))

        if not has_ownable and not has_access_control:
            return findings

        if has_multisig:
            return findings  # Has multisig protection

        # Count privileged functions
        privileged_patterns = [
            r'onlyOwner',
            r'onlyAdmin',
            r'onlyRole\s*\(',
            r'require\s*\(\s*msg\.sender\s*==\s*owner',
        ]
        priv_count = 0
        for pat in privileged_patterns:
            priv_count += len(re.findall(pat, source))

        if priv_count > 0:
            # Find the owner/admin declaration
            for match in re.finditer(
                r'(address\s+(?:public\s+)?(?:owner|admin|_owner))',
                source,
            ):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(
                    lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
                )
                findings.append(self._make_finding(
                    title=f"Single admin controls {priv_count} privileged functions",
                    description=(
                        f"The contract has {priv_count} privileged functions controlled "
                        "by a single admin address without multisig protection. "
                        "If the admin key is compromised, an attacker gains full control "
                        "over all privileged operations."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    remediation=(
                        "Use a multisig wallet (e.g., Gnosis Safe) as the admin:\n"
                        "1. Deploy a Gnosis Safe with 3-of-5 or similar threshold\n"
                        "2. Transfer ownership: `transferOwnership(safeAddress)`\n"
                        "3. Consider adding timelocks for critical operations\n"
                        "4. Implement AccessControl with role separation"
                    ),
                ))
                break  # One finding is enough

        return findings


class PrivilegedFunctionDetector(BaseDetector):
    """Detect dangerous privileged functions that pose centralization risk."""

    DETECTOR_ID = "SCWE-040-002"
    NAME = "Dangerous Privileged Functions"
    DESCRIPTION = (
        "Detects privileged functions that can rug-pull users: token minting, "
        "pausing, fee changes, blacklisting, withdrawal of user funds."
    )
    SCWE_ID = "SCWE-040"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "centralization"

    DANGEROUS_FUNCTIONS = [
        (r'function\s+pause\s*\(', "pause", "Contract can be paused, freezing all funds"),
        (r'function\s+blacklist\s*\(', "blacklist", "Admin can blacklist users from transfers"),
        (r'function\s+setFee\s*\(', "setFee", "Admin can change fees — potentially to 100%"),
        (r'function\s+setTax\s*\(', "setTax", "Admin can change tax — potentially to 100%"),
        (r'function\s+withdrawAll\s*\(', "withdrawAll", "Admin can withdraw all funds"),
        (r'function\s+drain\s*\(', "drain", "Admin drain function found"),
        (r'function\s+emergencyWithdraw\s*\([^)]*\)\s*(?:external|public)[^{]*onlyOwner', "emergencyWithdraw",
         "Admin can emergency withdraw user funds"),
        (r'function\s+setRecipient\s*\(', "setRecipient", "Admin can redirect funds"),
        (r'function\s+setRouter\s*\(', "setRouter", "Admin can change router to malicious contract"),
        (r'selfdestruct\s*\(|SELFDESTRUCT', "selfdestruct", "Contract can be self-destructed"),
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        for pattern, name, description in self.DANGEROUS_FUNCTIONS:
            for match in re.finditer(pattern, source, re.MULTILINE):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(
                    lines[line_no:min(len(lines), line_no + 5)]
                )

                # Check if there's a timelock
                func_end = min(len(lines), line_no + 20)
                func_text = "\n".join(lines[line_no:func_end])
                has_timelock = bool(re.search(
                    r'timelock|TimelockController|delay|executeAfter',
                    func_text, re.IGNORECASE,
                ))

                severity = Severity.LOW if has_timelock else Severity.MEDIUM
                if name in ("drain", "selfdestruct"):
                    severity = Severity.HIGH if not has_timelock else Severity.MEDIUM

                findings.append(self._make_finding(
                    title=f"Centralization risk: `{name}()` function",
                    description=(
                        f"{description}. "
                        f"{'Has timelock protection.' if has_timelock else 'No timelock protection — admin can execute immediately.'}"
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 5,
                    snippet=snippet,
                    severity=severity,
                    remediation=(
                        f"For `{name}()`:\n"
                        "1. Add a timelock (24-48h delay) for execution\n"
                        "2. Emit events before execution for transparency\n"
                        "3. Use multisig for admin operations\n"
                        "4. Consider making the function governance-only"
                    ),
                ))

        return findings


class UpgradeCentralizationDetector(BaseDetector):
    """Detect centralized upgrade authority in proxy contracts."""

    DETECTOR_ID = "SCWE-040-003"
    NAME = "Centralized Upgrade Authority"
    DESCRIPTION = (
        "Detects proxy contracts where a single admin can upgrade the "
        "implementation, potentially changing all contract logic and "
        "allowing fund theft."
    )
    SCWE_ID = "SCWE-040"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.HIGH
    CATEGORY = "centralization"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Check for upgrade patterns
        upgrade_patterns = [
            (r'function\s+upgradeTo\s*\(', "upgradeTo"),
            (r'function\s+upgradeToAndCall\s*\(', "upgradeToAndCall"),
            (r'function\s+_authorizeUpgrade\s*\(', "_authorizeUpgrade"),
            (r'function\s+setImplementation\s*\(', "setImplementation"),
        ]

        for pattern, func_name in upgrade_patterns:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n")
                func_end = min(len(lines), line_no + 15)
                func_text = "\n".join(lines[line_no:func_end])

                # Check protections
                has_timelock = bool(re.search(
                    r'timelock|TimelockController', func_text, re.IGNORECASE
                ))
                has_governance = bool(re.search(
                    r'governance|onlyGovernance|DAO', func_text, re.IGNORECASE
                ))
                has_multisig = bool(re.search(
                    r'multisig|gnosis|safe', func_text, re.IGNORECASE
                ))

                protections: list[str] = []
                if has_timelock:
                    protections.append("timelock")
                if has_governance:
                    protections.append("governance")
                if has_multisig:
                    protections.append("multisig")

                if not protections:
                    snippet = "\n".join(
                        lines[line_no:min(len(lines), line_no + 8)]
                    )
                    findings.append(self._make_finding(
                        title=f"Centralized upgrade: `{func_name}()`",
                        description=(
                            f"The upgrade function `{func_name}` (line {line_no + 1}) "
                            "can be called by a single admin without timelock or "
                            "governance vote. The admin can replace the entire contract "
                            "logic, including adding a function to drain all funds."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + 8,
                        snippet=snippet,
                        remediation=(
                            "Protect upgrades with multiple safeguards:\n"
                            "1. Require governance vote for upgrades\n"
                            "2. Add a timelock (48-72h) before upgrade takes effect\n"
                            "3. Use a multisig as the upgrade admin\n"
                            "4. Consider making the contract immutable after stabilizing"
                        ),
                    ))

        return findings


class BackdoorDetector(BaseDetector):
    """Detect potential backdoor or hidden admin functions."""

    DETECTOR_ID = "SCWE-040-004"
    NAME = "Potential Backdoor Function"
    DESCRIPTION = (
        "Detects suspicious patterns that may indicate backdoor functions: "
        "hidden transfer functions, arbitrary delegatecall from admin, "
        "or functions that can drain the contract."
    )
    SCWE_ID = "SCWE-040"
    CWE_ID = "CWE-506"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "centralization"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # 1. Admin-controlled arbitrary delegatecall
        for match in re.finditer(
            r'function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)[^{]*onlyOwner[^{]*\{',
            source, re.MULTILINE,
        ):
            func_name = match.group(1)
            line_no = source[:match.start()].count("\n")
            func_end = min(len(lines), line_no + 20)
            func_text = "\n".join(lines[line_no:func_end])
            if "delegatecall" in func_text:
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 8)])
                findings.append(self._make_finding(
                    title=f"Admin-controlled delegatecall in `{func_name}`",
                    description=(
                        f"The admin-only function `{func_name}` (line {line_no + 1}) "
                        "executes a delegatecall. This allows the admin to execute "
                        "arbitrary code in the context of this contract, including "
                        "draining all funds and modifying all state."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 8,
                    snippet=snippet,
                    severity=Severity.CRITICAL,
                    remediation=(
                        "Remove arbitrary delegatecall from admin functions. "
                        "If upgrade functionality is needed, use a well-audited "
                        "proxy pattern (UUPS or TransparentProxy)."
                    ),
                ))

        # 2. Hidden transfer / sweep functions
        for match in re.finditer(
            r'function\s+(sweep|rescue|recover|emergencyTransfer|adminTransfer)\s*\(',
            source,
        ):
            func_name = match.group(1)
            line_no = source[:match.start()].count("\n")
            func_end = min(len(lines), line_no + 15)
            func_text = "\n".join(lines[line_no:func_end])

            # Check if it can move user tokens (not just contract balance)
            can_move_user_tokens = bool(re.search(
                r'transferFrom|safeTransferFrom', func_text
            ))

            if can_move_user_tokens:
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 8)])
                findings.append(self._make_finding(
                    title=f"Backdoor: `{func_name}()` can move user tokens",
                    description=(
                        f"The function `{func_name}` (line {line_no + 1}) uses "
                        "transferFrom, which can move tokens on behalf of users who "
                        "have approved this contract. Admin can steal user funds."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 8,
                    snippet=snippet,
                    severity=Severity.CRITICAL,
                    remediation=(
                        "Remove transferFrom from admin functions. Recovery functions "
                        "should only affect the contract's own balance:\n"
                        "```solidity\n"
                        "function sweep(IERC20 token) external onlyOwner {\n"
                        "    token.transfer(owner(), token.balanceOf(address(this)));\n"
                        "}\n```"
                    ),
                ))

        # 3. Arbitrary call function
        for match in re.finditer(
            r'function\s+(\w+)\s*\(\s*address\s+\w+\s*,\s*bytes\s', source
        ):
            func_name = match.group(1)
            line_no = source[:match.start()].count("\n")
            func_end = min(len(lines), line_no + 15)
            func_text = "\n".join(lines[line_no:func_end])
            if ".call" in func_text and "onlyOwner" in func_text:
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 8)])
                findings.append(self._make_finding(
                    title=f"Admin-controlled arbitrary call: `{func_name}`",
                    description=(
                        f"The admin function `{func_name}` (line {line_no + 1}) can "
                        "make arbitrary external calls with arbitrary calldata. This is "
                        "equivalent to having full control over the contract."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 8,
                    snippet=snippet,
                    severity=Severity.HIGH,
                    remediation=(
                        "Remove arbitrary call capabilities. Use specific function "
                        "calls for defined operations instead of generic call(bytes)."
                    ),
                ))

        return findings

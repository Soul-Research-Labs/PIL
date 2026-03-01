"""Code quality and best practices detectors — SCWE-060, SCWE-061, SCWE-062, SCWE-009.

Detect floating pragma, outdated compiler, dead code, deprecated functions,
and other code quality issues.
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class FloatingPragmaDetector(BaseDetector):
    """Detect floating pragma versions."""

    DETECTOR_ID = "SCWE-060-001"
    NAME = "Floating Pragma"
    DESCRIPTION = (
        "Detects use of floating pragma (^, >=, ~) which can lead to "
        "contracts being compiled with different compiler versions, "
        "potentially introducing inconsistencies or vulnerabilities."
    )
    SCWE_ID = "SCWE-060"
    CWE_ID = "CWE-1103"
    SEVERITY = Severity.LOW
    CATEGORY = "code_quality"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        for i, line in enumerate(lines):
            match = re.match(r'\s*pragma\s+solidity\s+([\^~>=<]+)', line)
            if match and match.group(1) in ("^", ">=", "~", ">"):
                snippet = line.strip()
                findings.append(self._make_finding(
                    title="Floating pragma version",
                    description=(
                        f"The contract uses a floating pragma: `{line.strip()}`. "
                        "Contracts should be deployed with the same compiler version "
                        "they were tested with. Locking the pragma ensures consistent behavior."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=i + 1,
                    end_line=i + 1,
                    snippet=snippet,
                    remediation=(
                        "Lock the pragma to a specific version:\n"
                        "```solidity\n"
                        "pragma solidity 0.8.28;\n"
                        "```"
                    ),
                ))

        return findings


class OutdatedCompilerDetector(BaseDetector):
    """Detect use of outdated Solidity compiler versions."""

    DETECTOR_ID = "SCWE-061-001"
    NAME = "Outdated Compiler Version"
    DESCRIPTION = (
        "Detects use of Solidity compiler versions with known bugs or "
        "missing security features."
    )
    SCWE_ID = "SCWE-061"
    CWE_ID = "CWE-1104"
    SEVERITY = Severity.LOW
    CATEGORY = "code_quality"

    MINIMUM_SAFE_VERSION = (0, 8, 20)

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        for i, line in enumerate(lines):
            match = re.search(r'pragma\s+solidity\s*[\^~>=]*\s*((\d+)\.(\d+)\.(\d+))', line)
            if match:
                version_str = match.group(1)
                major, minor, patch = int(match.group(2)), int(match.group(3)), int(match.group(4))

                if (major, minor, patch) < self.MINIMUM_SAFE_VERSION:
                    findings.append(self._make_finding(
                        title=f"Outdated compiler version: {version_str}",
                        description=(
                            f"The contract specifies Solidity {version_str}. "
                            f"Versions below {'.'.join(map(str, self.MINIMUM_SAFE_VERSION))} "
                            "may contain known compiler bugs. Consider upgrading."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                        remediation=(
                            f"Upgrade to Solidity >= {'.'.join(map(str, self.MINIMUM_SAFE_VERSION))}:\n"
                            "```solidity\n"
                            "pragma solidity 0.8.28;\n"
                            "```"
                        ),
                    ))

        return findings


class DeprecatedFunctionsDetector(BaseDetector):
    """Detect use of deprecated Solidity functions."""

    DETECTOR_ID = "SCWE-009-001"
    NAME = "Deprecated Function Usage"
    DESCRIPTION = (
        "Detects use of deprecated Solidity functions that may be removed "
        "in future versions or have known security issues."
    )
    SCWE_ID = "SCWE-009"
    CWE_ID = "CWE-477"
    SEVERITY = Severity.LOW
    CATEGORY = "code_quality"

    DEPRECATED = [
        ("block.blockhash(", "blockhash(", "Use blockhash() instead of block.blockhash()"),
        ("msg.gas", "gasleft()", "Use gasleft() instead of msg.gas"),
        ("throw;", "revert()", "Use revert() instead of throw"),
        ("sha3(", "keccak256(", "Use keccak256() instead of sha3()"),
        ("suicide(", "selfdestruct(", "Use selfdestruct() instead of suicide()"),
        ("callcode(", "delegatecall(", "Use delegatecall() instead of callcode()"),
        (".send(", ".call{value:}(", "Use .call{value:}() instead of .send()"),
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        for deprecated, replacement, message in self.DEPRECATED:
            for i, line in enumerate(lines):
                if deprecated in line and not line.strip().startswith("//"):
                    snippet = line.strip()
                    findings.append(self._make_finding(
                        title=f"Deprecated: `{deprecated.rstrip('(')}`",
                        description=f"{message}. Deprecated functions may be removed in future Solidity versions.",
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=snippet,
                        remediation=f"Replace `{deprecated}` with `{replacement}`.",
                    ))

        return findings


class MissingEventEmissionDetector(BaseDetector):
    """Detect state-changing functions that don't emit events."""

    DETECTOR_ID = "SCWE-063-001"
    NAME = "Missing Event Emission"
    DESCRIPTION = (
        "Detects state-changing functions that modify critical variables "
        "without emitting events, reducing transparency and auditability."
    )
    SCWE_ID = "SCWE-063"
    CWE_ID = "CWE-778"
    SEVERITY = Severity.INFORMATIONAL
    CATEGORY = "code_quality"

    CRITICAL_SETTERS = [
        "setOwner", "transferOwnership", "setAdmin",
        "setFee", "setRate", "setPrice", "setLimit",
        "pause", "unpause", "setOracle", "setRouter",
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        for setter in self.CRITICAL_SETTERS:
            pattern = re.compile(
                rf'function\s+{setter}\s*\([^)]*\)\s+(?:public|external)[^{{]*\{{',
            )
            for match in pattern.finditer(source):
                # Check if the function body contains emit
                func_start = match.end()
                brace_count = 1
                func_end = func_start
                for j, char in enumerate(source[func_start:]):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                    if brace_count == 0:
                        func_end = func_start + j
                        break

                func_body = source[func_start:func_end]
                if "emit " not in func_body:
                    line_no = source[:match.start()].count("\n") + 1
                    snippet = "\n".join(
                        lines[max(0, line_no - 1):min(len(lines), line_no + 3)]
                    )
                    findings.append(self._make_finding(
                        title=f"Missing event in `{setter}`",
                        description=(
                            f"The function `{setter}` modifies critical state but does "
                            "not emit an event. Events are essential for off-chain "
                            "monitoring and transparency."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no,
                        end_line=line_no + 3,
                        snippet=snippet,
                        remediation=(
                            "Add an event emission:\n"
                            "```solidity\n"
                            f"event {setter[0].upper() + setter[1:]}Updated(...);\n"
                            f"function {setter}(...) external {{\n"
                            "    // state change\n"
                            f"    emit {setter[0].upper() + setter[1:]}Updated(...);\n"
                            "}\n```"
                        ),
                    ))

        return findings

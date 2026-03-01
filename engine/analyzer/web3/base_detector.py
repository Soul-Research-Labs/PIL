"""Base detector class — all smart contract detectors inherit from this."""

from __future__ import annotations

import abc
import re
from dataclasses import dataclass, field
from typing import Any

from engine.core.types import FindingSchema, Location, Severity


@dataclass
class DetectorContext:
    """Context passed to every detector during analysis.

    Contains the parsed AST, source code, compilation artifacts,
    and any previously-detected findings from other detectors.
    """

    source_code: str = ""
    source_files: dict[str, str] = field(default_factory=dict)
    ast: dict[str, Any] = field(default_factory=dict)
    sources_ast: dict[str, Any] = field(default_factory=dict)
    abi: list[dict[str, Any]] = field(default_factory=list)
    bytecode: str = ""
    storage_layout: dict[str, Any] = field(default_factory=dict)
    compiler_version: str = ""
    contract_name: str = ""
    contract_address: str = ""
    chain: str = ""
    # Populated during analysis
    previous_findings: list[FindingSchema] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── Helper accessors ─────────────────────────────────────────────────

    @property
    def lines(self) -> list[str]:
        """Split source into lines (cached via lru in practice)."""
        return self.source_code.split("\n")

    @property
    def has_reentrancy_guard(self) -> bool:
        return "nonReentrant" in self.source_code or "ReentrancyGuard" in self.source_code

    @property
    def solidity_version(self) -> tuple[int, int, int]:
        """Parse the pragma solidity version from source."""
        match = re.search(
            r'pragma\s+solidity\s+[^;]*?(\d+)\.(\d+)\.(\d+)', self.source_code
        )
        if match:
            return int(match.group(1)), int(match.group(2)), int(match.group(3))
        return (0, 8, 0)  # default to 0.8.0

    @property
    def is_upgradeable(self) -> bool:
        return any(kw in self.source_code for kw in [
            "Initializable", "initializer", "UUPSUpgradeable",
            "TransparentUpgradeableProxy", "ERC1967",
        ])

    @property
    def function_signatures(self) -> list[tuple[str, int, str]]:
        """Return list of (function_name, line_number, visibility)."""
        result: list[tuple[str, int, str]] = []
        for i, line in enumerate(self.source_code.split("\n")):
            m = re.match(r'\s*function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?', line)
            if m:
                result.append((m.group(1), i + 1, m.group(2) or ""))
        return result


class BaseDetector(abc.ABC):
    """Abstract base class for all smart contract vulnerability detectors.

    Each detector implements the `detect()` method which receives
    a DetectorContext and returns any findings.

    Detector metadata:
        - DETECTOR_ID: Unique identifier (e.g., "SCWE-046-001")
        - NAME: Human-readable detector name
        - DESCRIPTION: What this detector looks for
        - SCWE_ID: OWASP Smart Contract Weakness Enumeration ID
        - CWE_ID: Common Weakness Enumeration ID (optional)
        - SEVERITY: Default severity level
        - CATEGORY: High-level category for grouping
        - CONFIDENCE: Default confidence score (0.0–1.0)
    """

    DETECTOR_ID: str = ""
    NAME: str = ""
    DESCRIPTION: str = ""
    SCWE_ID: str = ""
    CWE_ID: str = ""
    SEVERITY: Severity = Severity.MEDIUM
    CATEGORY: str = ""
    CONFIDENCE: float = 0.8  # Default static detector confidence

    @abc.abstractmethod
    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        """Run the detector against the given context.

        Args:
            context: DetectorContext containing AST, source, and metadata

        Returns:
            List of findings detected. Empty if no issues found.
        """
        ...

    def _make_finding(
        self,
        title: str,
        description: str,
        file_path: str,
        start_line: int,
        end_line: int,
        snippet: str = "",
        severity: Severity | None = None,
        confidence: float | None = None,
        remediation: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> FindingSchema:
        """Helper to create a FindingSchema with this detector's metadata."""
        return FindingSchema(
            title=title,
            description=description,
            severity=severity or self.SEVERITY,
            confidence=confidence if confidence is not None else self.CONFIDENCE,
            category=self.CATEGORY,
            cwe_id=self.CWE_ID,
            scwe_id=self.SCWE_ID,
            location=Location(
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                snippet=snippet,
            ),
            remediation=remediation,
            metadata={
                "detector_id": self.DETECTOR_ID,
                "detector_name": self.NAME,
                **(metadata or {}),
            },
        )

"""Slither static analysis integration.

Runs Slither on Solidity source code and parses the JSON results
into the scanner's FindingSchema format, deduplicating against
findings from the internal detector pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from engine.core.types import FindingSchema, Location, Severity

logger = logging.getLogger(__name__)

# Map Slither impact levels to our severity enum
_SLITHER_SEVERITY: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
    "Optimization": Severity.GAS,
}

# Slither detector IDs considered very high confidence
_HIGH_CONFIDENCE_DETECTORS: set[str] = {
    "reentrancy-eth",
    "reentrancy-no-eth",
    "suicidal",
    "uninitialized-state",
    "arbitrary-send-eth",
    "controlled-delegatecall",
    "unprotected-upgrade",
    "unchecked-transfer",
    "reentrancy-unlimited-gas",
    "locked-ether",
    "incorrect-equality",
}


class SlitherRunner:
    """Wraps the `slither` CLI to produce structured findings."""

    def __init__(
        self,
        solc_version: str = "0.8.20",
        timeout: int = 120,
        extra_args: list[str] | None = None,
    ) -> None:
        self.solc_version = solc_version
        self.timeout = timeout
        self.extra_args = extra_args or []
        self._available: bool | None = None

    # ── Public API ───────────────────────────────────────────────────

    async def is_available(self) -> bool:
        """Check if slither is installed and reachable."""
        if self._available is not None:
            return self._available
        self._available = shutil.which("slither") is not None
        return self._available

    async def analyze_source(
        self,
        source_code: str,
        filename: str = "Contract.sol",
    ) -> list[FindingSchema]:
        """Run Slither on source code string and return findings."""
        if not await self.is_available():
            logger.warning("Slither not installed — skipping Slither analysis")
            return []

        tmpdir = tempfile.mkdtemp(prefix="zaseon_slither_")
        try:
            # Write source to temp file
            src_path = Path(tmpdir) / filename
            src_path.write_text(source_code, encoding="utf-8")

            return await self._run_slither(str(src_path), tmpdir)
        except Exception as exc:
            logger.error("Slither analysis failed: %s", exc)
            return []
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    async def analyze_directory(
        self,
        directory: str,
    ) -> list[FindingSchema]:
        """Run Slither on a project directory (e.g., Foundry/Hardhat)."""
        if not await self.is_available():
            logger.warning("Slither not installed — skipping Slither analysis")
            return []

        try:
            return await self._run_slither(directory, directory)
        except Exception as exc:
            logger.error("Slither analysis failed: %s", exc)
            return []

    async def analyze_files(
        self,
        files: dict[str, str],
    ) -> list[FindingSchema]:
        """Run Slither on multiple source files.

        Args:
            files: Mapping of filename → source code
        """
        if not files:
            return []
        if not await self.is_available():
            logger.warning("Slither not installed — skipping Slither analysis")
            return []

        tmpdir = tempfile.mkdtemp(prefix="zaseon_slither_")
        try:
            for fname, code in files.items():
                fpath = Path(tmpdir) / fname
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(code, encoding="utf-8")

            # Run slither on the directory
            return await self._run_slither(tmpdir, tmpdir)
        except Exception as exc:
            logger.error("Slither analysis failed: %s", exc)
            return []
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Private ──────────────────────────────────────────────────────

    async def _run_slither(self, target: str, cwd: str) -> list[FindingSchema]:
        """Execute slither CLI and parse output."""
        json_output = Path(cwd) / "slither_output.json"

        cmd = [
            "slither",
            target,
            "--json",
            str(json_output),
            "--solc-solcs-select",
            self.solc_version,
            "--exclude-informational",  # skip noisy info detectors
            "--exclude-optimization",  # we have our own gas detectors
            *self.extra_args,
        ]

        env = os.environ.copy()
        env["SLITHER_DISABLE_COLOR"] = "1"

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            logger.warning("Slither timed out after %ds", self.timeout)
            try:
                process.kill()
            except ProcessLookupError:
                pass
            return []

        if not json_output.exists():
            logger.warning("Slither produced no JSON output; stderr: %s", stderr.decode(errors="replace")[:500])
            return []

        try:
            raw = json.loads(json_output.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Slither JSON: %s", exc)
            return []

        return self._parse_results(raw)

    def _parse_results(self, raw: dict[str, Any]) -> list[FindingSchema]:
        """Convert Slither JSON output to FindingSchema list."""
        findings: list[FindingSchema] = []
        detectors = raw.get("results", {}).get("detectors", [])

        for det in detectors:
            check = det.get("check", "unknown")
            impact = det.get("impact", "Informational")
            confidence = det.get("confidence", "Medium")
            description = det.get("description", "").strip()
            first_markdown = det.get("first_markdown_element", "")

            severity = _SLITHER_SEVERITY.get(impact, Severity.INFORMATIONAL)

            # Map Slither confidence to our float scale
            conf_map = {"High": 0.95, "Medium": 0.75, "Low": 0.55}
            conf_value = conf_map.get(confidence, 0.6)

            # Boost confidence for known high-quality detectors
            if check in _HIGH_CONFIDENCE_DETECTORS:
                conf_value = min(conf_value + 0.1, 1.0)

            # Extract location from elements
            location = self._extract_location(det.get("elements", []))

            # Build category from Slither check name
            category = self._check_to_category(check)

            finding = FindingSchema(
                title=f"[Slither] {self._format_check_name(check)}",
                description=description,
                severity=severity,
                category=category,
                location=location,
                confidence=conf_value,
                recommendation=self._get_recommendation(check),
                references=[f"https://github.com/crytic/slither/wiki/Detector-Documentation#{check}"],
                metadata={
                    "source": "slither",
                    "detector": check,
                    "slither_confidence": confidence,
                    "slither_impact": impact,
                },
            )
            findings.append(finding)

        logger.info("Slither produced %d findings", len(findings))
        return findings

    def _extract_location(self, elements: list[dict]) -> Location:
        """Extract source location from Slither elements."""
        for el in elements:
            src_mapping = el.get("source_mapping", {})
            filename = src_mapping.get("filename_relative", "") or src_mapping.get("filename_short", "")
            start_line = src_mapping.get("starting_column", 0)
            lines = src_mapping.get("lines", [])

            if lines:
                return Location(
                    file_path=filename or "unknown",
                    start_line=min(lines),
                    end_line=max(lines),
                    snippet="",
                )

        return Location(file_path="unknown", start_line=0, end_line=0, snippet="")

    def _format_check_name(self, check: str) -> str:
        """Convert slither check ID to human-readable title."""
        return check.replace("-", " ").replace("_", " ").title()

    def _check_to_category(self, check: str) -> str:
        """Map Slither check to our finding category."""
        category_map: dict[str, str] = {
            "reentrancy": "reentrancy",
            "suicidal": "access-control",
            "unprotected": "access-control",
            "arbitrary-send": "access-control",
            "controlled-delegatecall": "delegatecall",
            "unchecked": "unchecked-returns",
            "locked-ether": "code-quality",
            "incorrect-equality": "arithmetic",
            "shadowing": "code-quality",
            "assembly": "code-quality",
            "timestamp": "defi",
            "weak-prng": "defi",
            "tx-origin": "access-control",
            "uninitialized": "storage",
            "storage": "storage",
            "erc20": "token-standard",
            "erc721": "token-standard",
        }
        for prefix, cat in category_map.items():
            if prefix in check:
                return cat
        return "general"

    def _get_recommendation(self, check: str) -> str:
        """Provide a brief recommendation for Slither findings."""
        recommendations: dict[str, str] = {
            "reentrancy-eth": "Apply checks-effects-interactions pattern or use ReentrancyGuard.",
            "reentrancy-no-eth": "Apply checks-effects-interactions pattern, update state before external calls.",
            "suicidal": "Add access control to selfdestruct. Consider removing it entirely.",
            "arbitrary-send-eth": "Restrict ETH transfer recipients to validated addresses only.",
            "controlled-delegatecall": "Never allow user-supplied addresses as delegatecall targets.",
            "unprotected-upgrade": "Add onlyOwner or initializer modifier to upgrade functions.",
            "unchecked-transfer": "Check the return value of ERC20 transfer/transferFrom calls.",
            "locked-ether": "Add a withdraw function or remove the payable fallback.",
            "incorrect-equality": "Use >= or <= instead of == for balance checks.",
            "tx-origin": "Use msg.sender instead of tx.origin for authentication.",
            "uninitialized-state": "Initialize all state variables in the constructor.",
        }
        for prefix, rec in recommendations.items():
            if prefix in check:
                return rec
        return "Review the flagged code and apply appropriate security measures."


def merge_slither_findings(
    internal_findings: list[FindingSchema],
    slither_findings: list[FindingSchema],
    similarity_threshold: int = 5,
) -> list[FindingSchema]:
    """Merge Slither findings with internal findings, deduplicating overlaps.

    If a Slither finding overlaps with an internal finding on the same
    category at a nearby line range (within `similarity_threshold` lines),
    the internal finding gets a confidence boost instead of duplicating.

    Returns the merged list.
    """
    boosted: set[int] = set()  # indices of internal findings already boosted
    new_from_slither: list[FindingSchema] = []

    for sf in slither_findings:
        matched = False
        for idx, inf in enumerate(internal_findings):
            if idx in boosted:
                continue
            # Check overlap: same category, nearby lines
            if sf.category == inf.category and sf.location.file_path == inf.location.file_path:
                line_diff = abs(sf.location.start_line - inf.location.start_line)
                if line_diff <= similarity_threshold:
                    # Boost internal finding confidence
                    inf.confidence = min(inf.confidence + 0.15, 1.0)
                    if not inf.metadata:
                        inf.metadata = {}
                    inf.metadata["slither_corroborated"] = True
                    boosted.add(idx)
                    matched = True
                    break

        if not matched:
            new_from_slither.append(sf)

    return internal_findings + new_from_slither

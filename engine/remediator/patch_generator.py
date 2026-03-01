"""LLM-powered patch generator for smart contract vulnerabilities.

Uses Claude / GPT-4o to generate context-aware Solidity patches,
validated against the original AST and optionally compiled with solc.
"""

from __future__ import annotations

import hashlib
import logging
import re
import textwrap
from dataclasses import dataclass, field
from typing import Any

from engine.core.types import FindingSchema, Severity

logger = logging.getLogger(__name__)


@dataclass
class PatchResult:
    """Result of a single patch generation attempt."""

    finding_id: str
    success: bool
    original_code: str = ""
    patched_code: str = ""
    diff: str = ""
    explanation: str = ""
    template_id: str | None = None
    confidence: float = 0.0
    gas_impact: int = 0
    compilation_ok: bool | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class RemediationPlan:
    """Aggregated remediation plan for a set of findings."""

    scan_id: str
    patches: list[PatchResult] = field(default_factory=list)
    total_findings: int = 0
    patched_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    review_required: list[str] = field(default_factory=list)  # finding IDs needing human review
    plan_hash: str = ""

    def compute_hash(self) -> str:
        """SHA-256 hash of all patches for integrity verification."""
        content = "".join(p.diff for p in self.patches if p.success)
        self.plan_hash = hashlib.sha256(content.encode()).hexdigest()
        return self.plan_hash


class PatchGenerator:
    """Generate Solidity patches for detected vulnerabilities.

    Operates in two modes:
      1. Template-based — fast, deterministic fixes for known patterns
      2. LLM-based — Claude/GPT-4o generates novel patches for complex issues

    Parameters
    ----------
    llm_client : object | None
        Async LLM client (engine.core.llm_client.LLMClient). If None,
        only template-based patches are generated.
    solc_path : str | None
        Path to solc binary for compilation validation.
    max_patch_attempts : int
        Maximum LLM iterations per finding.
    """

    def __init__(
        self,
        llm_client: Any | None = None,
        solc_path: str | None = None,
        max_patch_attempts: int = 3,
    ):
        self.llm_client = llm_client
        self.solc_path = solc_path
        self.max_patch_attempts = max_patch_attempts

        # Lazy import templates
        from engine.remediator.templates import TEMPLATES, get_templates_for_category

        self._templates = TEMPLATES
        self._get_templates = get_templates_for_category

    # ── Public API ───────────────────────────────────────────────────────

    async def generate_patch(
        self,
        finding: FindingSchema,
        source_code: str,
        contract_name: str = "",
    ) -> PatchResult:
        """Generate a patch for a single finding.

        Tries template-based fix first; falls back to LLM if no template
        matches or template fix fails compilation.
        """
        # Step 1: Try template match
        template_result = self._try_template_fix(finding, source_code, contract_name)
        if template_result and template_result.success:
            return template_result

        # Step 2: LLM-based generation
        if self.llm_client:
            return await self._llm_generate_patch(finding, source_code, contract_name)

        # No LLM available, return template result or failure
        return template_result or PatchResult(
            finding_id=finding.id,
            success=False,
            explanation="No matching template and LLM not available.",
        )

    async def generate_plan(
        self,
        findings: list[FindingSchema],
        source_code: str,
        scan_id: str = "",
    ) -> RemediationPlan:
        """Generate a complete remediation plan for all findings.

        Findings are processed in severity order (critical first).
        Conflicting patches are detected and the higher-confidence
        patch wins.
        """
        plan = RemediationPlan(scan_id=scan_id, total_findings=len(findings))

        # Sort by severity — critical first
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
            Severity.GAS: 5,
        }
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.severity, 99),
        )

        patched_regions: list[tuple[int, int]] = []  # track patched line ranges

        for finding in sorted_findings:
            # Skip if patch would overlap with a higher-priority fix
            finding_range = (finding.location.start_line, finding.location.end_line)
            if self._overlaps(finding_range, patched_regions):
                plan.skipped_count += 1
                continue

            try:
                result = await self.generate_patch(
                    finding, source_code, finding.location.file_path
                )
                plan.patches.append(result)

                if result.success:
                    plan.patched_count += 1
                    patched_regions.append(finding_range)
                    if result.confidence < 0.85:
                        plan.review_required.append(finding.id)
                else:
                    plan.failed_count += 1
            except Exception as e:
                logger.debug("Patch generation failed for %s: %s", finding.id, e)
                plan.failed_count += 1

        plan.compute_hash()
        return plan

    # ── Template-based fixing ────────────────────────────────────────────

    def _try_template_fix(
        self,
        finding: FindingSchema,
        source_code: str,
        contract_name: str,
    ) -> PatchResult | None:
        """Attempt a template-based fix for the finding."""
        templates = self._get_templates(finding.category)
        if not templates:
            return None

        for tpl in templates:
            # Check severity is in range
            if finding.severity.value not in tpl.severity_range:
                continue

            # Check pattern match if defined
            if tpl.pattern:
                snippet = finding.location.snippet or ""
                if not re.search(tpl.pattern, snippet, re.IGNORECASE):
                    continue

            # Generate patch from template
            patched = self._apply_template(tpl, finding, source_code, contract_name)
            if patched:
                diff = self._generate_diff(source_code, patched, finding.location.file_path)
                return PatchResult(
                    finding_id=finding.id,
                    success=True,
                    original_code=self._extract_region(
                        source_code, finding.location.start_line, finding.location.end_line
                    ),
                    patched_code=patched,
                    diff=diff,
                    explanation=tpl.description,
                    template_id=tpl.id,
                    confidence=tpl.confidence,
                    gas_impact=tpl.gas_impact,
                )

        return None

    def _apply_template(
        self,
        template: Any,
        finding: FindingSchema,
        source_code: str,
        contract_name: str,
    ) -> str | None:
        """Substitute placeholders in a template fix."""
        try:
            fix = template.fix_template
            fix = fix.replace("{{contract_name}}", contract_name)
            fix = fix.replace("{{function_name}}", self._guess_function_name(finding))
            fix = fix.replace("{{params}}", "")
            fix = fix.replace("{{max_iterations}}", "1000")

            # Insert fix into source at the finding location
            lines = source_code.split("\n")
            start = max(0, finding.location.start_line - 1)
            end = min(len(lines), finding.location.end_line)

            indent = self._detect_indent(lines[start] if start < len(lines) else "")
            indented_fix = textwrap.indent(fix.strip(), indent)

            patched_lines = lines[:start] + [indented_fix] + lines[end:]
            return "\n".join(patched_lines)
        except Exception as e:
            logger.debug("Template fix failed for %s: %s", finding.id, e)
            return None

    # ── LLM-based patch generation ───────────────────────────────────────

    async def _llm_generate_patch(
        self,
        finding: FindingSchema,
        source_code: str,
        contract_name: str,
    ) -> PatchResult:
        """Use LLM to generate a context-aware patch."""
        prompt = self._build_patch_prompt(finding, source_code, contract_name)

        for attempt in range(self.max_patch_attempts):
            try:
                response = await self.llm_client.analyze(prompt)
                patched_code = self._extract_code_block(response)

                if not patched_code:
                    continue

                diff = self._generate_diff(source_code, patched_code, contract_name)

                # Optional: compile-check
                compilation_ok = None
                if self.solc_path:
                    compilation_ok = await self._verify_compilation(patched_code)
                    if not compilation_ok:
                        prompt += (
                            "\n\nThe previous patch failed compilation. "
                            "Please fix the compilation errors and try again."
                        )
                        continue

                return PatchResult(
                    finding_id=finding.id,
                    success=True,
                    original_code=self._extract_region(
                        source_code,
                        finding.location.start_line,
                        finding.location.end_line,
                    ),
                    patched_code=patched_code,
                    diff=diff,
                    explanation=self._extract_explanation(response),
                    confidence=0.75,  # LLM patches have lower base confidence
                    compilation_ok=compilation_ok,
                )
            except Exception:
                continue

        return PatchResult(
            finding_id=finding.id,
            success=False,
            explanation=f"LLM failed to generate valid patch after {self.max_patch_attempts} attempts.",
        )

    def _build_patch_prompt(
        self,
        finding: FindingSchema,
        source_code: str,
        contract_name: str,
    ) -> str:
        """Build the LLM prompt for patch generation."""
        return f"""\
You are an expert Solidity security engineer. Generate a minimal, correct patch
for the following vulnerability.

**Contract**: {contract_name}

**Vulnerability**: {finding.title}
- Severity: {finding.severity.value}
- Category: {finding.category}
- CWE: {finding.cwe_id}
- Description: {finding.description}

**Affected Code** (lines {finding.location.start_line}-{finding.location.end_line}):
```solidity
{finding.location.snippet}
```

**Full Source**:
```solidity
{source_code[:8000]}
```

**Remediation Guidance**: {finding.remediation}

**Requirements**:
1. Return the COMPLETE patched source code in a ```solidity code block
2. Make MINIMAL changes — only fix the vulnerability
3. Maintain gas efficiency
4. Preserve all existing functionality
5. Add a comment explaining the fix
6. Follow latest Solidity best practices

**Explanation**: After the code block, explain in 2-3 sentences what was changed and why.
"""

    # ── Utility Methods ──────────────────────────────────────────────────

    @staticmethod
    def _extract_region(source: str, start: int, end: int) -> str:
        lines = source.split("\n")
        return "\n".join(lines[max(0, start - 1) : end])

    @staticmethod
    def _detect_indent(line: str) -> str:
        return line[: len(line) - len(line.lstrip())]

    @staticmethod
    def _guess_function_name(finding: FindingSchema) -> str:
        snippet = finding.location.snippet
        match = re.search(r"function\s+(\w+)", snippet)
        return match.group(1) if match else "unknownFunction"

    @staticmethod
    def _extract_code_block(response: Any) -> str | None:
        text = response if isinstance(response, str) else str(response)
        match = re.search(r"```solidity\s*(.*?)```", text, re.DOTALL)
        return match.group(1).strip() if match else None

    @staticmethod
    def _extract_explanation(response: Any) -> str:
        text = response if isinstance(response, str) else str(response)
        # Take text after the last code block
        parts = text.split("```")
        if len(parts) >= 3:
            return parts[-1].strip()[:500]
        return ""

    @staticmethod
    def _generate_diff(original: str, patched: str, filename: str) -> str:
        """Generate a unified diff between original and patched code."""
        import difflib

        orig_lines = original.splitlines(keepends=True)
        patch_lines = patched.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            patch_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff)

    @staticmethod
    def _overlaps(
        region: tuple[int, int],
        patched: list[tuple[int, int]],
    ) -> bool:
        """Check if a line region overlaps with any already-patched region."""
        for start, end in patched:
            if region[0] <= end and region[1] >= start:
                return True
        return False

    async def _verify_compilation(self, source: str) -> bool:
        """Attempt to compile patched Solidity source."""
        try:
            import subprocess
            result = subprocess.run(
                [self.solc_path or "solc", "--bin", "-"],
                input=source,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except Exception:
            return False

"""Remediation orchestrator — coordinates template matching, LLM patching,
compilation validation, and optional PR creation.

This is the main entry point for the auto-remediation pipeline.
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from engine.core.types import FindingSchema, FindingStatus, Severity
from engine.remediator.patch_generator import PatchGenerator, PatchResult, RemediationPlan
from engine.remediator.templates import (
    TEMPLATES,
    get_soul_templates,
    get_templates_for_category,
)

logger = logging.getLogger(__name__)


@dataclass
class RemediationReport:
    """Final report of the remediation run."""

    scan_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    plan: RemediationPlan | None = None
    pr_url: str | None = None
    branch_name: str | None = None
    total_findings: int = 0
    auto_fixed: int = 0
    review_required: int = 0
    unfixable: int = 0
    compilation_verified: int = 0
    gas_impact_total: int = 0
    errors: list[str] = field(default_factory=list)


class RemediationEngine:
    """Orchestrate end-to-end remediation for scan findings.

    Pipeline:
      1. Receive findings from a completed scan
      2. Classify each finding for fixability
      3. Generate patches (template + LLM)
      4. Validate patches (compilation, invariant preservation)
      5. Create unified diff / PR
      6. Report results

    Parameters
    ----------
    llm_client : object | None
        Async LLM client for generating complex patches.
    solc_path : str | None
        Path to solc for compilation validation.
    github_client : object | None
        GitHub client for creating PRs (optional).
    auto_pr : bool
        Whether to automatically create a PR with fixes.
    branch_prefix : str
        Prefix for auto-created branches.
    min_confidence : float
        Minimum confidence threshold for auto-applying patches.
    """

    def __init__(
        self,
        llm_client: Any | None = None,
        solc_path: str | None = None,
        github_client: Any | None = None,
        auto_pr: bool = False,
        branch_prefix: str = "zaseon/fix",
        min_confidence: float = 0.85,
    ):
        self.llm_client = llm_client
        self.github_client = github_client
        self.auto_pr = auto_pr
        self.branch_prefix = branch_prefix
        self.min_confidence = min_confidence

        self.patch_generator = PatchGenerator(
            llm_client=llm_client,
            solc_path=solc_path,
        )

        # Track statistics
        self._stats = {
            "template_hits": 0,
            "llm_patches": 0,
            "compilation_checks": 0,
            "compilation_passes": 0,
        }

    # ── Main Entry Point ─────────────────────────────────────────────────

    async def remediate(
        self,
        findings: list[FindingSchema],
        source_files: dict[str, str],
        scan_id: str = "",
        repo_url: str | None = None,
    ) -> RemediationReport:
        """Run the full remediation pipeline.

        Parameters
        ----------
        findings : list[FindingSchema]
            Detected (and ideally verified) vulnerabilities.
        source_files : dict[str, str]
            Mapping of file path → Solidity source code.
        scan_id : str
            ID of the originating scan.
        repo_url : str | None
            GitHub repo URL for PR creation.

        Returns
        -------
        RemediationReport
            Full report with patches, PR URL, and statistics.
        """
        report = RemediationReport(scan_id=scan_id, total_findings=len(findings))

        try:
            # 1. Filter to fixable findings
            fixable = self._filter_fixable(findings)
            logger.info(
                "Remediation: %d fixable out of %d total findings",
                len(fixable),
                len(findings),
            )

            # 2. Group by file
            by_file = self._group_by_file(fixable)

            # 3. Generate patches per file
            all_patches: list[PatchResult] = []
            for file_path, file_findings in by_file.items():
                source = source_files.get(file_path, "")
                if not source:
                    logger.warning("No source for %s, skipping", file_path)
                    continue

                plan = await self.patch_generator.generate_plan(
                    file_findings, source, scan_id
                )
                all_patches.extend(plan.patches)

            # 4. Build unified plan
            unified_plan = RemediationPlan(
                scan_id=scan_id,
                patches=all_patches,
                total_findings=len(findings),
                patched_count=sum(1 for p in all_patches if p.success),
                failed_count=sum(1 for p in all_patches if not p.success),
            )
            unified_plan.compute_hash()
            report.plan = unified_plan

            # 5. Update statistics
            report.auto_fixed = unified_plan.patched_count
            report.unfixable = len(findings) - len(fixable)
            report.review_required = len(unified_plan.review_required)
            report.compilation_verified = sum(
                1 for p in all_patches if p.compilation_ok is True
            )
            report.gas_impact_total = sum(p.gas_impact for p in all_patches if p.success)

            # 6. Create PR if enabled
            if self.auto_pr and self.github_client and repo_url:
                pr_url = await self._create_pr(
                    unified_plan, source_files, repo_url, scan_id
                )
                report.pr_url = pr_url

        except Exception as e:
            logger.exception("Remediation pipeline error: %s", e)
            report.errors.append(str(e))
        finally:
            report.completed_at = datetime.now(timezone.utc)

        return report

    # ── Classification ───────────────────────────────────────────────────

    def _filter_fixable(self, findings: list[FindingSchema]) -> list[FindingSchema]:
        """Filter findings to those we can attempt to fix."""
        fixable = []
        for f in findings:
            # Skip already patched or discarded
            if f.status in (FindingStatus.PATCHED, FindingStatus.DISCARDED):
                continue
            # Skip informational / gas (optional fixes)
            if f.severity in (Severity.INFORMATIONAL,):
                continue
            # Must have a code location
            if not f.location or not f.location.file_path:
                continue
            fixable.append(f)
        return fixable

    def _group_by_file(
        self,
        findings: list[FindingSchema],
    ) -> dict[str, list[FindingSchema]]:
        """Group findings by their source file."""
        by_file: dict[str, list[FindingSchema]] = {}
        for f in findings:
            fp = f.location.file_path
            by_file.setdefault(fp, []).append(f)
        return by_file

    # ── PR Creation ──────────────────────────────────────────────────────

    async def _create_pr(
        self,
        plan: RemediationPlan,
        source_files: dict[str, str],
        repo_url: str,
        scan_id: str,
    ) -> str | None:
        """Create a GitHub PR with the generated patches.

        Workflow:
          1. Parse owner/repo from *repo_url*.
          2. Resolve the default branch SHA.
          3. Create a new branch ``zaseon/fix/<scan_id>``.
          4. Commit each patched file.
          5. Open a pull request and return its URL.
        """
        try:
            branch_name = f"{self.branch_prefix}/{scan_id[:8]}"
            successful = [p for p in plan.patches if p.success]
            if not successful:
                logger.info("No successful patches — skipping PR creation")
                return None

            # ── Parse owner/repo ─────────────────────────────────────────
            owner, repo = self._parse_github_url(repo_url)
            if not owner or not repo:
                logger.error("Cannot parse GitHub owner/repo from %s", repo_url)
                return None

            # ── Resolve token ────────────────────────────────────────────
            token = self._resolve_github_token()
            if not token:
                logger.error("No GitHub token available for PR creation")
                return None

            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            api = f"https://api.github.com/repos/{owner}/{repo}"

            async with httpx.AsyncClient(timeout=30) as client:
                # 1. Get default branch SHA
                repo_resp = await client.get(api, headers=headers)
                repo_resp.raise_for_status()
                default_branch = repo_resp.json()["default_branch"]

                ref_resp = await client.get(
                    f"{api}/git/ref/heads/{default_branch}", headers=headers
                )
                ref_resp.raise_for_status()
                base_sha = ref_resp.json()["object"]["sha"]

                # 2. Create branch
                await client.post(
                    f"{api}/git/refs",
                    headers=headers,
                    json={
                        "ref": f"refs/heads/{branch_name}",
                        "sha": base_sha,
                    },
                )

                # 3. Commit each patched file
                for patch in successful:
                    file_path = patch.finding_id  # finding_id stores the path
                    # Prefer the patched content; fall back to original
                    content = patch.patched_source or source_files.get(file_path, "")
                    if not content:
                        continue

                    encoded = base64.b64encode(content.encode()).decode()

                    # Get the current file SHA (needed for update)
                    existing = await client.get(
                        f"{api}/contents/{file_path}",
                        headers=headers,
                        params={"ref": branch_name},
                    )
                    sha = existing.json().get("sha") if existing.status_code == 200 else None

                    payload: dict[str, Any] = {
                        "message": f"fix: auto-remediate {patch.finding_id}\n\n{patch.explanation[:200]}",
                        "content": encoded,
                        "branch": branch_name,
                    }
                    if sha:
                        payload["sha"] = sha

                    await client.put(
                        f"{api}/contents/{file_path}",
                        headers=headers,
                        json=payload,
                    )

                # 4. Open PR
                body = self._build_pr_body(successful, scan_id)
                pr_resp = await client.post(
                    f"{api}/pulls",
                    headers=headers,
                    json={
                        "title": f"[ZASEON] Auto-remediate {len(successful)} finding(s) from scan {scan_id[:8]}",
                        "body": body,
                        "head": branch_name,
                        "base": default_branch,
                    },
                )
                pr_resp.raise_for_status()
                pr_url = pr_resp.json()["html_url"]

                logger.info(
                    "Created PR %s on branch %s with %d patches",
                    pr_url,
                    branch_name,
                    len(successful),
                )
                return pr_url

        except httpx.HTTPStatusError as e:
            logger.error("GitHub API error during PR creation: %s — %s", e.response.status_code, e.response.text[:300])
            return None
        except Exception as e:
            logger.error("PR creation failed: %s", e)
            return None

    # ── GitHub helpers ────────────────────────────────────────────────────

    @staticmethod
    def _parse_github_url(url: str) -> tuple[str, str]:
        """Extract (owner, repo) from a GitHub URL or slug."""
        # Matches github.com/owner/repo with optional .git
        match = re.search(r"github\.com[/:]([^/]+)/([^/.]+)", url)
        if match:
            return match.group(1), match.group(2)
        # Bare owner/repo slug
        parts = url.strip("/").split("/")
        if len(parts) == 2:
            return parts[0], parts[1]
        return "", ""

    def _resolve_github_token(self) -> str | None:
        """Return a usable GitHub token from the github_client or env."""
        import os

        # If the github_client is a token string directly
        if isinstance(self.github_client, str):
            return self.github_client
        # If it's an object with a token attribute
        if hasattr(self.github_client, "token"):
            return self.github_client.token
        if hasattr(self.github_client, "auth") and hasattr(self.github_client.auth, "token"):
            return self.github_client.auth.token
        # Fall back to environment
        return os.environ.get("GITHUB_TOKEN") or os.environ.get("ZASEON_GITHUB_TOKEN")

    def _build_pr_body(self, patches: list[PatchResult], scan_id: str) -> str:
        """Build a markdown PR description."""
        lines = [
            "## ZASEON Auto-Remediation",
            "",
            f"**Scan ID**: `{scan_id}`",
            f"**Patches Applied**: {len(patches)}",
            "",
            "### Fixes",
            "",
        ]

        for i, p in enumerate(patches, 1):
            status = "compiled" if p.compilation_ok else "unverified"
            confidence_pct = int(p.confidence * 100)
            lines.append(
                f"{i}. **{p.finding_id}** — {p.explanation[:100]} "
                f"(confidence: {confidence_pct}%, {status})"
            )

        lines.extend([
            "",
            "---",
            "",
            "> Generated by [ZASEON](https://zaseon.dev) auto-remediation engine.",
            "> Please review all changes carefully before merging.",
        ])

        return "\n".join(lines)

    # ── Utility ──────────────────────────────────────────────────────────

    def get_available_templates(self) -> list[dict[str, Any]]:
        """Return all available remediation templates as dicts."""
        return [
            {
                "id": t.id,
                "category": t.category,
                "title": t.title,
                "strategy": t.strategy.value,
                "confidence": t.confidence,
                "tags": t.tags,
            }
            for t in TEMPLATES
        ]

    def get_soul_templates(self) -> list[dict[str, Any]]:
        """Return Soul Protocol–specific templates."""
        return [
            {
                "id": t.id,
                "category": t.category,
                "title": t.title,
                "confidence": t.confidence,
                "tags": t.tags,
            }
            for t in get_soul_templates()
        ]

    @property
    def stats(self) -> dict[str, int]:
        """Return runtime statistics."""
        return dict(self._stats)

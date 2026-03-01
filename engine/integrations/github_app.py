"""GitHub App integration — auto-scan on PR, commit status checks.

Provides:
- JWT-based GitHub App authentication (RS256)
- Installation token management
- PR webhook processing (opened, synchronize, reopened)
- Check Run creation/update with inline annotations
- Auto-scan trigger on push/PR events
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx
import jwt

from engine.core.config import get_settings

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


# ── Enums / Data ─────────────────────────────────────────────────────────────


class CheckStatus(str, Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class CheckConclusion(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    NEUTRAL = "neutral"
    CANCELLED = "cancelled"
    ACTION_REQUIRED = "action_required"


@dataclass
class CheckAnnotation:
    """Maps a finding to a GitHub Check Run annotation."""
    path: str
    start_line: int
    end_line: int
    annotation_level: str  # notice | warning | failure
    title: str
    message: str
    raw_details: str = ""


@dataclass
class PRContext:
    """Parsed context from a GitHub PR webhook event."""
    installation_id: int
    repo_owner: str
    repo_name: str
    repo_full_name: str
    pr_number: int
    head_sha: str
    base_branch: str
    head_branch: str
    action: str  # opened, synchronize, reopened, closed
    sender: str
    clone_url: str


# ── GitHub App Auth ──────────────────────────────────────────────────────────


class GitHubAppAuth:
    """Manages GitHub App JWT and installation token lifecycle.

    The App authenticates with an RS256 JWT signed by its private key,
    then exchanges it for a short-lived installation access token
    scoped to a specific repository installation.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._token_cache: dict[int, tuple[str, float]] = {}  # install_id -> (token, expires_at)

    def _create_app_jwt(self) -> str:
        """Create a JWT for GitHub App authentication (valid 10 minutes)."""
        now = int(time.time())
        payload = {
            "iat": now - 60,  # 60s clock drift allowance
            "exp": now + (10 * 60),
            "iss": self._settings.github_app_id,
        }
        private_key = self._settings.github_app_private_key
        if not private_key:
            raise ValueError("ZASEON_GITHUB_APP_PRIVATE_KEY not configured")

        # Handle escaped newlines in env var
        if "\\n" in private_key:
            private_key = private_key.replace("\\n", "\n")

        return jwt.encode(payload, private_key, algorithm="RS256")

    async def get_installation_token(self, installation_id: int) -> str:
        """Get or refresh an installation access token.

        Tokens are cached until 5 minutes before expiry.
        """
        cached = self._token_cache.get(installation_id)
        if cached:
            token, expires_at = cached
            if time.time() < expires_at - 300:  # 5 min buffer
                return token

        app_jwt = self._create_app_jwt()
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        token = data["token"]
        expires_at = datetime.fromisoformat(
            data["expires_at"].replace("Z", "+00:00")
        ).timestamp()

        self._token_cache[installation_id] = (token, expires_at)
        logger.info("Refreshed installation token for installation %d", installation_id)
        return token


# ── Webhook verification ─────────────────────────────────────────────────────


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature.

    Args:
        payload: Raw request body bytes.
        signature: ``X-Hub-Signature-256`` header value (``sha256=...``).

    Returns:
        True if the signature is valid.
    """
    settings = get_settings()
    secret = settings.github_webhook_secret.encode()
    if not secret:
        logger.warning("GITHUB_WEBHOOK_SECRET not set — skipping verification")
        return True

    if not signature.startswith("sha256="):
        return False

    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    actual = signature[7:]  # strip 'sha256=' prefix
    return hmac.compare_digest(expected, actual)


# ── PR event parsing ─────────────────────────────────────────────────────────


def parse_pr_event(event: dict[str, Any]) -> PRContext | None:
    """Parse a ``pull_request`` webhook event into a PRContext.

    Returns None for actions we don't care about (e.g., labeled, assigned).
    """
    action = event.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return None

    pr = event.get("pull_request", {})
    repo = event.get("repository", {})
    installation = event.get("installation", {})

    return PRContext(
        installation_id=installation.get("id", 0),
        repo_owner=repo.get("owner", {}).get("login", ""),
        repo_name=repo.get("name", ""),
        repo_full_name=repo.get("full_name", ""),
        pr_number=pr.get("number", 0),
        head_sha=pr.get("head", {}).get("sha", ""),
        base_branch=pr.get("base", {}).get("ref", "main"),
        head_branch=pr.get("head", {}).get("ref", ""),
        action=action,
        sender=event.get("sender", {}).get("login", ""),
        clone_url=repo.get("clone_url", ""),
    )


def parse_push_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a ``push`` webhook event.

    Returns dict with repo info and head commit, or None for tag pushes.
    """
    ref = event.get("ref", "")
    if not ref.startswith("refs/heads/"):
        return None

    repo = event.get("repository", {})
    installation = event.get("installation", {})

    return {
        "installation_id": installation.get("id", 0),
        "repo_owner": repo.get("owner", {}).get("login", ""),
        "repo_name": repo.get("name", ""),
        "repo_full_name": repo.get("full_name", ""),
        "branch": ref.replace("refs/heads/", ""),
        "head_sha": event.get("after", ""),
        "clone_url": repo.get("clone_url", ""),
    }


# ── Check Runs ───────────────────────────────────────────────────────────────


class GitHubCheckRunManager:
    """Creates and updates GitHub Check Runs to report scan results on PRs.

    A Check Run shows as a status check on the PR with:
    - Summary of findings by severity
    - Inline annotations on affected lines
    - Action button to view full report on ZASEON dashboard
    """

    def __init__(self, auth: GitHubAppAuth) -> None:
        self._auth = auth

    async def create_check_run(
        self,
        installation_id: int,
        repo_full_name: str,
        head_sha: str,
        name: str = "ZASEON Security Scan",
    ) -> int:
        """Create a new Check Run in 'queued' state. Returns the check_run_id."""
        token = await self._auth.get_installation_token(installation_id)

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GITHUB_API}/repos/{repo_full_name}/check-runs",
                headers=_gh_headers(token),
                json={
                    "name": name,
                    "head_sha": head_sha,
                    "status": "queued",
                    "external_id": str(uuid.uuid4()),
                },
            )
            resp.raise_for_status()
            data = resp.json()

        check_run_id = data["id"]
        logger.info("Created check run %d for %s @ %s", check_run_id, repo_full_name, head_sha[:8])
        return check_run_id

    async def update_check_in_progress(
        self,
        installation_id: int,
        repo_full_name: str,
        check_run_id: int,
    ) -> None:
        """Move Check Run to ``in_progress``."""
        token = await self._auth.get_installation_token(installation_id)
        async with httpx.AsyncClient() as client:
            await client.patch(
                f"{GITHUB_API}/repos/{repo_full_name}/check-runs/{check_run_id}",
                headers=_gh_headers(token),
                json={
                    "status": "in_progress",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                },
            )

    async def complete_check_run(
        self,
        installation_id: int,
        repo_full_name: str,
        check_run_id: int,
        conclusion: CheckConclusion,
        summary: str,
        annotations: list[CheckAnnotation] | None = None,
        details_url: str | None = None,
    ) -> None:
        """Complete a Check Run with findings summary and annotations.

        GitHub limits annotations to 50 per request, so we batch if needed.
        """
        token = await self._auth.get_installation_token(installation_id)

        output: dict[str, Any] = {
            "title": "ZASEON Security Scan",
            "summary": summary,
        }

        annotation_dicts = [
            {
                "path": a.path,
                "start_line": a.start_line,
                "end_line": a.end_line,
                "annotation_level": a.annotation_level,
                "title": a.title,
                "message": a.message,
                **({"raw_details": a.raw_details} if a.raw_details else {}),
            }
            for a in (annotations or [])
        ]

        # Send first batch (up to 50 annotations)
        first_batch = annotation_dicts[:50]
        if first_batch:
            output["annotations"] = first_batch

        body: dict[str, Any] = {
            "status": "completed",
            "conclusion": conclusion.value,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "output": output,
        }
        if details_url:
            body["details_url"] = details_url

        async with httpx.AsyncClient() as client:
            await client.patch(
                f"{GITHUB_API}/repos/{repo_full_name}/check-runs/{check_run_id}",
                headers=_gh_headers(token),
                json=body,
            )

            # Send remaining annotation batches
            remaining = annotation_dicts[50:]
            while remaining:
                batch = remaining[:50]
                remaining = remaining[50:]
                await client.patch(
                    f"{GITHUB_API}/repos/{repo_full_name}/check-runs/{check_run_id}",
                    headers=_gh_headers(token),
                    json={"output": {"title": "ZASEON Security Scan", "summary": summary, "annotations": batch}},
                )

        logger.info(
            "Completed check run %d: %s (%d annotations)",
            check_run_id,
            conclusion.value,
            len(annotation_dicts),
        )


# ── Scan orchestration ───────────────────────────────────────────────────────


def findings_to_annotations(
    findings: list[dict[str, Any]],
) -> list[CheckAnnotation]:
    """Convert ZASEON findings into GitHub Check Run annotations."""
    severity_to_level = {
        "critical": "failure",
        "high": "failure",
        "medium": "warning",
        "low": "notice",
        "informational": "notice",
        "gas": "notice",
    }

    annotations = []
    for f in findings:
        annotations.append(
            CheckAnnotation(
                path=f.get("file_path", ""),
                start_line=max(1, f.get("start_line", 1)),
                end_line=max(1, f.get("end_line", 1)),
                annotation_level=severity_to_level.get(f.get("severity", "medium"), "warning"),
                title=f.get("title", "Security Finding"),
                message=f.get("description", ""),
                raw_details=f.get("remediation", ""),
            )
        )
    return annotations


def findings_to_summary(findings: list[dict[str, Any]], security_score: float | None = None) -> str:
    """Generate a Markdown summary of findings for the Check Run."""
    by_sev: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    total = len(findings)
    lines = [f"## ZASEON Security Scan Results\n"]
    if security_score is not None:
        lines.append(f"**Security Score:** {security_score:.0f}/100\n")
    lines.append(f"**Total Findings:** {total}\n")

    if by_sev:
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "informational", "gas"]:
            count = by_sev.get(sev, 0)
            if count:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
                lines.append(f"| {emoji} {sev.title()} | {count} |")
        lines.append("")

    if total == 0:
        lines.append("✅ No security issues detected.")
    elif by_sev.get("critical", 0) > 0 or by_sev.get("high", 0) > 0:
        lines.append("⚠️ **Action required** — critical or high severity findings detected.")

    return "\n".join(lines)


def determine_conclusion(findings: list[dict[str, Any]]) -> CheckConclusion:
    """Determine check conclusion based on finding severities."""
    severities = {f.get("severity", "") for f in findings}
    if "critical" in severities:
        return CheckConclusion.FAILURE
    if "high" in severities:
        return CheckConclusion.ACTION_REQUIRED
    if "medium" in severities:
        return CheckConclusion.NEUTRAL
    return CheckConclusion.SUCCESS


# ── Helpers ──────────────────────────────────────────────────────────────────


def _gh_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

"""Multi-SCM integration — GitLab and Bitbucket support alongside GitHub.

Provides a unified interface for:
- Repository cloning (HTTPS/SSH)
- Webhook event parsing (push, MR/PR)
- Status checks / commit statuses
- Code annotations / inline comments
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# ── Models ───────────────────────────────────────────────────────────────────


class SCMProvider(str, Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"


class WebhookEventType(str, Enum):
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    MERGE_REQUEST = "merge_request"
    TAG = "tag"
    UNKNOWN = "unknown"


@dataclass
class SCMEvent:
    """Normalised webhook event across all providers."""

    provider: SCMProvider
    event_type: WebhookEventType
    repo_url: str
    ref: str  # branch or tag ref
    commit_sha: str
    author: str
    clone_url: str
    pr_number: int | None = None
    pr_title: str | None = None
    base_branch: str | None = None
    raw: dict = field(default_factory=dict)


@dataclass
class StatusReport:
    """Normalised status report to post back to the SCM."""

    state: str  # success, failure, pending, error
    description: str
    target_url: str = ""
    context: str = "zaseon/security-scan"


@dataclass
class CodeAnnotation:
    """Inline annotation for a finding on a specific file/line."""

    path: str
    line: int
    message: str
    severity: str  # error, warning, info


# ── Base SCM adapter ────────────────────────────────────────────────────────


class SCMAdapter(ABC):
    """Abstract base for SCM provider integrations."""

    @abstractmethod
    def verify_webhook(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify webhook signature."""
        ...

    @abstractmethod
    def parse_event(self, headers: dict[str, str], body: dict) -> SCMEvent:
        """Parse a webhook payload into a normalised SCMEvent."""
        ...

    @abstractmethod
    async def post_status(
        self, repo: str, commit_sha: str, status: StatusReport, token: str
    ) -> bool:
        """Post a commit status / check run."""
        ...

    @abstractmethod
    async def post_annotations(
        self, repo: str, commit_sha: str, annotations: list[CodeAnnotation], token: str
    ) -> bool:
        """Post inline code annotations (PR comments or code review)."""
        ...


# ── GitHub adapter ──────────────────────────────────────────────────────────


class GitHubAdapter(SCMAdapter):
    """GitHub API integration (v3 REST)."""

    API = "https://api.github.com"

    def verify_webhook(self, payload: bytes, signature: str, secret: str) -> bool:
        if not signature.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def parse_event(self, headers: dict[str, str], body: dict) -> SCMEvent:
        event_type_raw = headers.get("x-github-event", "")

        if event_type_raw == "push":
            return SCMEvent(
                provider=SCMProvider.GITHUB,
                event_type=WebhookEventType.PUSH,
                repo_url=body.get("repository", {}).get("html_url", ""),
                ref=body.get("ref", ""),
                commit_sha=body.get("after", ""),
                author=body.get("pusher", {}).get("name", ""),
                clone_url=body.get("repository", {}).get("clone_url", ""),
                raw=body,
            )
        elif event_type_raw == "pull_request":
            pr = body.get("pull_request", {})
            return SCMEvent(
                provider=SCMProvider.GITHUB,
                event_type=WebhookEventType.PULL_REQUEST,
                repo_url=body.get("repository", {}).get("html_url", ""),
                ref=pr.get("head", {}).get("ref", ""),
                commit_sha=pr.get("head", {}).get("sha", ""),
                author=pr.get("user", {}).get("login", ""),
                clone_url=body.get("repository", {}).get("clone_url", ""),
                pr_number=pr.get("number"),
                pr_title=pr.get("title"),
                base_branch=pr.get("base", {}).get("ref"),
                raw=body,
            )
        return SCMEvent(
            provider=SCMProvider.GITHUB,
            event_type=WebhookEventType.UNKNOWN,
            repo_url="", ref="", commit_sha="", author="", clone_url="",
            raw=body,
        )

    async def post_status(
        self, repo: str, commit_sha: str, status: StatusReport, token: str
    ) -> bool:
        url = f"{self.API}/repos/{repo}/statuses/{commit_sha}"
        async with httpx.AsyncClient() as client:
            r = await client.post(
                url,
                headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
                json={
                    "state": status.state,
                    "description": status.description[:140],
                    "target_url": status.target_url,
                    "context": status.context,
                },
            )
            return r.status_code in (200, 201)

    async def post_annotations(
        self, repo: str, commit_sha: str, annotations: list[CodeAnnotation], token: str
    ) -> bool:
        # Uses the Check Runs API
        url = f"{self.API}/repos/{repo}/check-runs"
        gh_annotations = [
            {
                "path": a.path,
                "start_line": a.line,
                "end_line": a.line,
                "annotation_level": a.severity,
                "message": a.message,
            }
            for a in annotations[:50]  # GitHub limit
        ]
        async with httpx.AsyncClient() as client:
            r = await client.post(
                url,
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                json={
                    "name": "ZASEON Security Scan",
                    "head_sha": commit_sha,
                    "status": "completed",
                    "conclusion": "neutral",
                    "output": {
                        "title": "ZASEON Findings",
                        "summary": f"{len(annotations)} security findings",
                        "annotations": gh_annotations,
                    },
                },
            )
            return r.status_code in (200, 201)


# ── GitLab adapter ──────────────────────────────────────────────────────────


class GitLabAdapter(SCMAdapter):
    """GitLab API integration (v4 REST)."""

    def __init__(self, base_url: str = "https://gitlab.com") -> None:
        self.api = f"{base_url}/api/v4"

    def verify_webhook(self, payload: bytes, signature: str, secret: str) -> bool:
        # GitLab uses X-Gitlab-Token header (plain token comparison)
        return hmac.compare_digest(signature, secret)

    def parse_event(self, headers: dict[str, str], body: dict) -> SCMEvent:
        event_type_raw = body.get("object_kind", "")

        if event_type_raw == "push":
            project = body.get("project", {})
            return SCMEvent(
                provider=SCMProvider.GITLAB,
                event_type=WebhookEventType.PUSH,
                repo_url=project.get("web_url", ""),
                ref=body.get("ref", ""),
                commit_sha=body.get("after", ""),
                author=body.get("user_name", ""),
                clone_url=project.get("git_http_url", ""),
                raw=body,
            )
        elif event_type_raw == "merge_request":
            mr = body.get("object_attributes", {})
            project = body.get("project", {})
            return SCMEvent(
                provider=SCMProvider.GITLAB,
                event_type=WebhookEventType.MERGE_REQUEST,
                repo_url=project.get("web_url", ""),
                ref=mr.get("source_branch", ""),
                commit_sha=mr.get("last_commit", {}).get("id", ""),
                author=body.get("user", {}).get("username", ""),
                clone_url=project.get("git_http_url", ""),
                pr_number=mr.get("iid"),
                pr_title=mr.get("title"),
                base_branch=mr.get("target_branch"),
                raw=body,
            )
        return SCMEvent(
            provider=SCMProvider.GITLAB,
            event_type=WebhookEventType.UNKNOWN,
            repo_url="", ref="", commit_sha="", author="", clone_url="",
            raw=body,
        )

    async def post_status(
        self, repo: str, commit_sha: str, status: StatusReport, token: str
    ) -> bool:
        # repo is project_id for GitLab
        state_map = {
            "success": "success",
            "failure": "failed",
            "pending": "pending",
            "error": "failed",
        }
        url = f"{self.api}/projects/{repo}/statuses/{commit_sha}"
        async with httpx.AsyncClient() as client:
            r = await client.post(
                url,
                headers={"PRIVATE-TOKEN": token},
                json={
                    "state": state_map.get(status.state, "pending"),
                    "description": status.description[:255],
                    "target_url": status.target_url,
                    "name": status.context,
                },
            )
            return r.status_code in (200, 201)

    async def post_annotations(
        self, repo: str, commit_sha: str, annotations: list[CodeAnnotation], token: str
    ) -> bool:
        # GitLab: post as MR discussion notes (one per annotation, batched)
        # For now, post a consolidated comment
        if not annotations:
            return True

        lines = [f"### 🛡️ ZASEON Security Findings ({len(annotations)})\n"]
        for a in annotations[:30]:
            icon = "🔴" if a.severity == "error" else "🟡" if a.severity == "warning" else "ℹ️"
            lines.append(f"- {icon} **{a.path}:{a.line}** — {a.message}")

        body = "\n".join(lines)

        # Post as a commit comment
        url = f"{self.api}/projects/{repo}/repository/commits/{commit_sha}/comments"
        async with httpx.AsyncClient() as client:
            r = await client.post(
                url,
                headers={"PRIVATE-TOKEN": token},
                json={"note": body},
            )
            return r.status_code in (200, 201)


# ── Bitbucket adapter ───────────────────────────────────────────────────────


class BitbucketAdapter(SCMAdapter):
    """Bitbucket Cloud API integration (2.0)."""

    API = "https://api.bitbucket.org/2.0"

    def verify_webhook(self, payload: bytes, signature: str, secret: str) -> bool:
        # Bitbucket Cloud doesn't have webhook signatures
        # Verify by checking the IP range or use Bitbucket Server with HMAC
        if not secret:
            return True  # No secret configured
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def parse_event(self, headers: dict[str, str], body: dict) -> SCMEvent:
        event_key = headers.get("x-event-key", "")

        if event_key == "repo:push":
            repo_data = body.get("repository", {})
            changes = body.get("push", {}).get("changes", [{}])
            latest = changes[0] if changes else {}
            new = latest.get("new", {})
            return SCMEvent(
                provider=SCMProvider.BITBUCKET,
                event_type=WebhookEventType.PUSH,
                repo_url=repo_data.get("links", {}).get("html", {}).get("href", ""),
                ref=new.get("name", ""),
                commit_sha=new.get("target", {}).get("hash", ""),
                author=body.get("actor", {}).get("display_name", ""),
                clone_url=repo_data.get("links", {}).get("html", {}).get("href", "") + ".git",
                raw=body,
            )
        elif event_key.startswith("pullrequest:"):
            pr = body.get("pullrequest", {})
            repo_data = body.get("repository", {})
            return SCMEvent(
                provider=SCMProvider.BITBUCKET,
                event_type=WebhookEventType.PULL_REQUEST,
                repo_url=repo_data.get("links", {}).get("html", {}).get("href", ""),
                ref=pr.get("source", {}).get("branch", {}).get("name", ""),
                commit_sha=pr.get("source", {}).get("commit", {}).get("hash", ""),
                author=pr.get("author", {}).get("display_name", ""),
                clone_url=repo_data.get("links", {}).get("html", {}).get("href", "") + ".git",
                pr_number=pr.get("id"),
                pr_title=pr.get("title"),
                base_branch=pr.get("destination", {}).get("branch", {}).get("name"),
                raw=body,
            )
        return SCMEvent(
            provider=SCMProvider.BITBUCKET,
            event_type=WebhookEventType.UNKNOWN,
            repo_url="", ref="", commit_sha="", author="", clone_url="",
            raw=body,
        )

    async def post_status(
        self, repo: str, commit_sha: str, status: StatusReport, token: str
    ) -> bool:
        # repo format: "workspace/repo_slug"
        state_map = {
            "success": "SUCCESSFUL",
            "failure": "FAILED",
            "pending": "INPROGRESS",
            "error": "FAILED",
        }
        url = f"{self.API}/repositories/{repo}/commit/{commit_sha}/statuses/build"
        async with httpx.AsyncClient() as client:
            r = await client.post(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "state": state_map.get(status.state, "INPROGRESS"),
                    "key": status.context,
                    "name": "ZASEON Security Scan",
                    "description": status.description[:255],
                    "url": status.target_url,
                },
            )
            return r.status_code in (200, 201)

    async def post_annotations(
        self, repo: str, commit_sha: str, annotations: list[CodeAnnotation], token: str
    ) -> bool:
        # Bitbucket: uses Reports + Annotations API
        report_id = "zaseon-scan"
        report_url = f"{self.API}/repositories/{repo}/commit/{commit_sha}/reports/{report_id}"

        sev_map = {
            "error": "CRITICAL",
            "warning": "MEDIUM",
            "info": "LOW",
        }

        async with httpx.AsyncClient() as client:
            # Create report
            await client.put(
                report_url,
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "title": "ZASEON Security Scan",
                    "report_type": "SECURITY",
                    "result": "FAILED" if any(a.severity == "error" for a in annotations) else "PASSED",
                    "details": f"{len(annotations)} security findings",
                },
            )

            # Add annotations
            bb_annotations = [
                {
                    "external_id": f"zaseon-{i}",
                    "path": a.path,
                    "line": a.line,
                    "summary": a.message[:450],
                    "severity": sev_map.get(a.severity, "MEDIUM"),
                    "annotation_type": "VULNERABILITY",
                }
                for i, a in enumerate(annotations[:100])
            ]

            r = await client.post(
                f"{report_url}/annotations",
                headers={"Authorization": f"Bearer {token}"},
                json=bb_annotations,
            )
            return r.status_code in (200, 201)


# ── Factory ──────────────────────────────────────────────────────────────────


def get_adapter(provider: SCMProvider | str) -> SCMAdapter:
    """Get the SCM adapter for the given provider."""
    provider = SCMProvider(provider) if isinstance(provider, str) else provider
    adapters: dict[SCMProvider, type[SCMAdapter]] = {
        SCMProvider.GITHUB: GitHubAdapter,
        SCMProvider.GITLAB: GitLabAdapter,
        SCMProvider.BITBUCKET: BitbucketAdapter,
    }
    cls = adapters.get(provider)
    if not cls:
        raise ValueError(f"Unsupported SCM provider: {provider}")
    return cls()


def detect_provider(headers: dict[str, str]) -> SCMProvider:
    """Auto-detect the SCM provider from webhook headers."""
    if "x-github-event" in headers:
        return SCMProvider.GITHUB
    if "x-gitlab-event" in headers or "x-gitlab-token" in headers:
        return SCMProvider.GITLAB
    if "x-event-key" in headers:
        return SCMProvider.BITBUCKET
    raise ValueError("Cannot detect SCM provider from webhook headers")

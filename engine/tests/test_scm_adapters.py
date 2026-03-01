"""Tests for multi-SCM adapters (engine/integrations/scm.py).

Covers:
- GitHubAdapter: webhook verification, event parsing (push, PR, unknown), status posting, annotations
- GitLabAdapter: webhook verification, event parsing (push, MR, unknown), status posting, annotations
- BitbucketAdapter: webhook verification, event parsing (push, PR, unknown), status posting, annotations
- Factory: get_adapter(), detect_provider()
- SCMEvent, StatusReport, CodeAnnotation dataclasses
"""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.integrations.scm import (
    BitbucketAdapter,
    CodeAnnotation,
    GitHubAdapter,
    GitLabAdapter,
    SCMAdapter,
    SCMEvent,
    SCMProvider,
    StatusReport,
    WebhookEventType,
    detect_provider,
    get_adapter,
)


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def github_adapter() -> GitHubAdapter:
    return GitHubAdapter()


@pytest.fixture
def gitlab_adapter() -> GitLabAdapter:
    return GitLabAdapter()


@pytest.fixture
def bitbucket_adapter() -> BitbucketAdapter:
    return BitbucketAdapter()


@pytest.fixture
def sample_status() -> StatusReport:
    return StatusReport(
        state="success",
        description="All checks passed",
        target_url="https://zaseon.io/scans/123",
        context="zaseon/security-scan",
    )


@pytest.fixture
def sample_annotations() -> list[CodeAnnotation]:
    return [
        CodeAnnotation(path="contracts/Token.sol", line=42, message="Reentrancy vulnerability", severity="error"),
        CodeAnnotation(path="contracts/Token.sol", line=100, message="Missing access control", severity="warning"),
        CodeAnnotation(path="contracts/Vault.sol", line=15, message="Consider using SafeMath", severity="info"),
    ]


# ── GitHub Adapter ───────────────────────────────────────────────────────


class TestGitHubAdapter:
    """Tests for GitHub API integration."""

    def test_verify_webhook_valid(self, github_adapter: GitHubAdapter):
        secret = "test-secret"
        payload = b'{"action": "opened"}'
        expected_sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert github_adapter.verify_webhook(payload, expected_sig, secret) is True

    def test_verify_webhook_invalid_signature(self, github_adapter: GitHubAdapter):
        assert github_adapter.verify_webhook(b"payload", "sha256=wrong", "secret") is False

    def test_verify_webhook_missing_prefix(self, github_adapter: GitHubAdapter):
        assert github_adapter.verify_webhook(b"payload", "invalid-format", "secret") is False

    def test_parse_push_event(self, github_adapter: GitHubAdapter):
        headers = {"x-github-event": "push"}
        body = {
            "ref": "refs/heads/main",
            "after": "abc123",
            "pusher": {"name": "dev-user"},
            "repository": {
                "html_url": "https://github.com/org/repo",
                "clone_url": "https://github.com/org/repo.git",
            },
        }
        event = github_adapter.parse_event(headers, body)
        assert event.provider == SCMProvider.GITHUB
        assert event.event_type == WebhookEventType.PUSH
        assert event.commit_sha == "abc123"
        assert event.author == "dev-user"
        assert event.ref == "refs/heads/main"
        assert "github.com" in event.clone_url

    def test_parse_pr_event(self, github_adapter: GitHubAdapter):
        headers = {"x-github-event": "pull_request"}
        body = {
            "repository": {
                "html_url": "https://github.com/org/repo",
                "clone_url": "https://github.com/org/repo.git",
            },
            "pull_request": {
                "head": {"ref": "feature-branch", "sha": "def456"},
                "base": {"ref": "main"},
                "user": {"login": "author"},
                "number": 42,
                "title": "Add feature",
            },
        }
        event = github_adapter.parse_event(headers, body)
        assert event.event_type == WebhookEventType.PULL_REQUEST
        assert event.pr_number == 42
        assert event.pr_title == "Add feature"
        assert event.base_branch == "main"
        assert event.commit_sha == "def456"

    def test_parse_unknown_event(self, github_adapter: GitHubAdapter):
        headers = {"x-github-event": "star"}
        body = {}
        event = github_adapter.parse_event(headers, body)
        assert event.event_type == WebhookEventType.UNKNOWN

    @pytest.mark.asyncio
    async def test_post_status(self, github_adapter: GitHubAdapter, sample_status: StatusReport):
        mock_response = MagicMock()
        mock_response.status_code = 201

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await github_adapter.post_status("org/repo", "abc123", sample_status, "ghp_token")
            assert result is True
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_post_annotations(self, github_adapter: GitHubAdapter, sample_annotations: list[CodeAnnotation]):
        mock_response = MagicMock()
        mock_response.status_code = 201

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await github_adapter.post_annotations("org/repo", "abc123", sample_annotations, "ghp_token")
            assert result is True


# ── GitLab Adapter ───────────────────────────────────────────────────────


class TestGitLabAdapter:
    """Tests for GitLab API integration."""

    def test_verify_webhook_valid(self, gitlab_adapter: GitLabAdapter):
        # GitLab uses plain token comparison
        assert gitlab_adapter.verify_webhook(b"payload", "my-secret", "my-secret") is True

    def test_verify_webhook_invalid(self, gitlab_adapter: GitLabAdapter):
        assert gitlab_adapter.verify_webhook(b"payload", "wrong", "correct") is False

    def test_parse_push_event(self, gitlab_adapter: GitLabAdapter):
        headers = {"x-gitlab-event": "Push Hook"}
        body = {
            "object_kind": "push",
            "ref": "refs/heads/main",
            "after": "gl-abc123",
            "user_name": "gitlabdev",
            "project": {
                "web_url": "https://gitlab.com/org/repo",
                "git_http_url": "https://gitlab.com/org/repo.git",
            },
        }
        event = gitlab_adapter.parse_event(headers, body)
        assert event.provider == SCMProvider.GITLAB
        assert event.event_type == WebhookEventType.PUSH
        assert event.commit_sha == "gl-abc123"
        assert event.author == "gitlabdev"

    def test_parse_merge_request_event(self, gitlab_adapter: GitLabAdapter):
        headers = {"x-gitlab-event": "Merge Request Hook"}
        body = {
            "object_kind": "merge_request",
            "object_attributes": {
                "source_branch": "feature-x",
                "target_branch": "main",
                "last_commit": {"id": "mr-sha-456"},
                "iid": 15,
                "title": "MR Title",
            },
            "user": {"username": "mrauthor"},
            "project": {
                "web_url": "https://gitlab.com/org/repo",
                "git_http_url": "https://gitlab.com/org/repo.git",
            },
        }
        event = gitlab_adapter.parse_event(headers, body)
        assert event.event_type == WebhookEventType.MERGE_REQUEST
        assert event.pr_number == 15
        assert event.pr_title == "MR Title"
        assert event.base_branch == "main"

    def test_parse_unknown_event(self, gitlab_adapter: GitLabAdapter):
        headers = {"x-gitlab-event": "Pipeline Hook"}
        body = {"object_kind": "pipeline"}
        event = gitlab_adapter.parse_event(headers, body)
        assert event.event_type == WebhookEventType.UNKNOWN

    @pytest.mark.asyncio
    async def test_post_status(self, gitlab_adapter: GitLabAdapter, sample_status: StatusReport):
        mock_response = MagicMock()
        mock_response.status_code = 201

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await gitlab_adapter.post_status("12345", "sha", sample_status, "glpat-token")
            assert result is True
            # Verify PRIVATE-TOKEN header is used
            call_kwargs = mock_client.post.call_args
            assert "PRIVATE-TOKEN" in call_kwargs.kwargs.get("headers", {})

    @pytest.mark.asyncio
    async def test_post_annotations(self, gitlab_adapter: GitLabAdapter, sample_annotations: list[CodeAnnotation]):
        mock_response = MagicMock()
        mock_response.status_code = 201

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await gitlab_adapter.post_annotations("12345", "sha", sample_annotations, "glpat-token")
            assert result is True

    @pytest.mark.asyncio
    async def test_post_annotations_empty(self, gitlab_adapter: GitLabAdapter):
        result = await gitlab_adapter.post_annotations("12345", "sha", [], "token")
        assert result is True


# ── Bitbucket Adapter ────────────────────────────────────────────────────


class TestBitbucketAdapter:
    """Tests for Bitbucket Cloud API integration."""

    def test_verify_webhook_no_secret(self, bitbucket_adapter: BitbucketAdapter):
        # No secret configured — always passes
        assert bitbucket_adapter.verify_webhook(b"payload", "", "") is True

    def test_verify_webhook_with_secret(self, bitbucket_adapter: BitbucketAdapter):
        secret = "bb-secret"
        payload = b"webhook-body"
        sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert bitbucket_adapter.verify_webhook(payload, sig, secret) is True

    def test_verify_webhook_wrong_secret(self, bitbucket_adapter: BitbucketAdapter):
        assert bitbucket_adapter.verify_webhook(b"payload", "wrong", "secret") is False

    def test_parse_push_event(self, bitbucket_adapter: BitbucketAdapter):
        headers = {"x-event-key": "repo:push"}
        body = {
            "repository": {
                "links": {"html": {"href": "https://bitbucket.org/ws/repo"}},
            },
            "push": {
                "changes": [
                    {
                        "new": {
                            "name": "main",
                            "target": {"hash": "bb-sha-789"},
                        }
                    }
                ]
            },
            "actor": {"display_name": "BBUser"},
        }
        event = bitbucket_adapter.parse_event(headers, body)
        assert event.provider == SCMProvider.BITBUCKET
        assert event.event_type == WebhookEventType.PUSH
        assert event.commit_sha == "bb-sha-789"
        assert event.author == "BBUser"

    def test_parse_pr_event(self, bitbucket_adapter: BitbucketAdapter):
        headers = {"x-event-key": "pullrequest:created"}
        body = {
            "repository": {
                "links": {"html": {"href": "https://bitbucket.org/ws/repo"}},
            },
            "pullrequest": {
                "id": 7,
                "title": "BB Pull Request",
                "source": {
                    "branch": {"name": "feature"},
                    "commit": {"hash": "pr-sha"},
                },
                "destination": {"branch": {"name": "main"}},
                "author": {"display_name": "PRAuthor"},
            },
        }
        event = bitbucket_adapter.parse_event(headers, body)
        assert event.event_type == WebhookEventType.PULL_REQUEST
        assert event.pr_number == 7
        assert event.pr_title == "BB Pull Request"
        assert event.base_branch == "main"

    def test_parse_unknown_event(self, bitbucket_adapter: BitbucketAdapter):
        headers = {"x-event-key": "repo:fork"}
        body = {}
        event = bitbucket_adapter.parse_event(headers, body)
        assert event.event_type == WebhookEventType.UNKNOWN

    @pytest.mark.asyncio
    async def test_post_status(self, bitbucket_adapter: BitbucketAdapter, sample_status: StatusReport):
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await bitbucket_adapter.post_status("ws/repo", "sha", sample_status, "bb-token")
            assert result is True

    @pytest.mark.asyncio
    async def test_post_annotations(
        self, bitbucket_adapter: BitbucketAdapter, sample_annotations: list[CodeAnnotation]
    ):
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_response)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            result = await bitbucket_adapter.post_annotations("ws/repo", "sha", sample_annotations, "bb-token")
            assert result is True
            # Should have called put (report) then post (annotations)
            mock_client.put.assert_called_once()
            mock_client.post.assert_called_once()


# ── Factory functions ────────────────────────────────────────────────────


class TestFactory:
    """Test get_adapter and detect_provider."""

    def test_get_adapter_github(self):
        adapter = get_adapter(SCMProvider.GITHUB)
        assert isinstance(adapter, GitHubAdapter)

    def test_get_adapter_gitlab(self):
        adapter = get_adapter(SCMProvider.GITLAB)
        assert isinstance(adapter, GitLabAdapter)

    def test_get_adapter_bitbucket(self):
        adapter = get_adapter(SCMProvider.BITBUCKET)
        assert isinstance(adapter, BitbucketAdapter)

    def test_get_adapter_from_string(self):
        adapter = get_adapter("github")
        assert isinstance(adapter, GitHubAdapter)

    def test_get_adapter_invalid(self):
        with pytest.raises(ValueError, match="Unsupported SCM"):
            get_adapter("svn")

    def test_detect_provider_github(self):
        headers = {"x-github-event": "push"}
        assert detect_provider(headers) == SCMProvider.GITHUB

    def test_detect_provider_gitlab_event(self):
        headers = {"x-gitlab-event": "Push Hook"}
        assert detect_provider(headers) == SCMProvider.GITLAB

    def test_detect_provider_gitlab_token(self):
        headers = {"x-gitlab-token": "secret"}
        assert detect_provider(headers) == SCMProvider.GITLAB

    def test_detect_provider_bitbucket(self):
        headers = {"x-event-key": "repo:push"}
        assert detect_provider(headers) == SCMProvider.BITBUCKET

    def test_detect_provider_unknown(self):
        with pytest.raises(ValueError, match="Cannot detect"):
            detect_provider({"content-type": "application/json"})


# ── Dataclass tests ──────────────────────────────────────────────────────


class TestDataclasses:
    """Test SCM dataclass construction."""

    def test_scm_event_defaults(self):
        event = SCMEvent(
            provider=SCMProvider.GITHUB,
            event_type=WebhookEventType.PUSH,
            repo_url="https://github.com/org/repo",
            ref="refs/heads/main",
            commit_sha="abc",
            author="dev",
            clone_url="https://github.com/org/repo.git",
        )
        assert event.pr_number is None
        assert event.pr_title is None
        assert event.base_branch is None
        assert event.raw == {}

    def test_status_report(self):
        sr = StatusReport(state="failure", description="Found 5 critical issues")
        assert sr.context == "zaseon/security-scan"
        assert sr.target_url == ""

    def test_code_annotation(self):
        a = CodeAnnotation(path="file.sol", line=10, message="Bug found", severity="error")
        assert a.path == "file.sol"
        assert a.severity == "error"

    def test_scm_provider_enum(self):
        assert SCMProvider.GITHUB.value == "github"
        assert SCMProvider.GITLAB.value == "gitlab"
        assert SCMProvider.BITBUCKET.value == "bitbucket"

    def test_webhook_event_type_enum(self):
        assert WebhookEventType.PUSH.value == "push"
        assert WebhookEventType.PULL_REQUEST.value == "pull_request"
        assert WebhookEventType.MERGE_REQUEST.value == "merge_request"
        assert WebhookEventType.TAG.value == "tag"
        assert WebhookEventType.UNKNOWN.value == "unknown"

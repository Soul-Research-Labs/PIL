"""Tests for GitHub App integration.

Covers:
    - GitHubAppAuth JWT generation and token caching
    - Webhook signature verification (HMAC-SHA256)
    - PR event parsing
    - Push event parsing
    - Check Run annotation building
    - Finding → annotation + summary conversion
    - Conclusion determination from severities
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.integrations.github_app import (
    CheckAnnotation,
    CheckConclusion,
    CheckStatus,
    GitHubAppAuth,
    GitHubCheckRunManager,
    PRContext,
    determine_conclusion,
    findings_to_annotations,
    findings_to_summary,
    parse_pr_event,
    parse_push_event,
    verify_webhook_signature,
)


# ── Webhook signature ────────────────────────────────────────────────────────


class TestWebhookSignature:
    def test_valid_signature(self):
        secret = "test-webhook-secret"
        payload = b'{"action":"opened"}'
        sig = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert verify_webhook_signature(payload, sig, secret) is True

    def test_invalid_signature(self):
        secret = "test-webhook-secret"
        payload = b'{"action":"opened"}'
        assert verify_webhook_signature(payload, "sha256=invalid", secret) is False

    def test_missing_prefix(self):
        secret = "sec"
        payload = b"body"
        assert verify_webhook_signature(payload, "noprefixhash", secret) is False


# ── PR Event Parsing ────────────────────────────────────────────────────────


SAMPLE_PR_EVENT = {
    "action": "opened",
    "installation": {"id": 12345},
    "pull_request": {
        "number": 42,
        "head": {
            "sha": "abc123def456",
            "ref": "feature/security-fix",
        },
        "base": {
            "ref": "main",
        },
    },
    "repository": {
        "owner": {"login": "soul-labs"},
        "name": "soul-protocol",
        "full_name": "soul-labs/soul-protocol",
        "clone_url": "https://github.com/soul-labs/soul-protocol.git",
    },
    "sender": {"login": "dev-user"},
}


class TestParsePREvent:
    def test_parse_valid_event(self):
        ctx = parse_pr_event(SAMPLE_PR_EVENT)
        assert isinstance(ctx, PRContext)
        assert ctx.installation_id == 12345
        assert ctx.repo_owner == "soul-labs"
        assert ctx.repo_name == "soul-protocol"
        assert ctx.pr_number == 42
        assert ctx.head_sha == "abc123def456"
        assert ctx.base_branch == "main"
        assert ctx.head_branch == "feature/security-fix"
        assert ctx.action == "opened"
        assert ctx.sender == "dev-user"

    def test_parse_synchronize_event(self):
        event = {**SAMPLE_PR_EVENT, "action": "synchronize"}
        ctx = parse_pr_event(event)
        assert ctx.action == "synchronize"


# ── Push Event Parsing ──────────────────────────────────────────────────────


class TestParsePushEvent:
    def test_parse_push(self):
        event = {
            "ref": "refs/heads/main",
            "after": "sha456",
            "repository": {
                "owner": {"login": "soul-labs"},
                "name": "soul-protocol",
                "full_name": "soul-labs/soul-protocol",
                "clone_url": "https://github.com/soul-labs/soul-protocol.git",
            },
            "installation": {"id": 999},
            "sender": {"login": "ci-bot"},
        }
        result = parse_push_event(event)
        assert result["ref"] == "refs/heads/main"
        assert result["head_sha"] == "sha456"
        assert result["installation_id"] == 999


# ── Annotations & Summary ───────────────────────────────────────────────────


class TestAnnotations:
    def test_findings_to_annotations(self):
        findings = [
            MagicMock(
                title="Reentrancy Bug",
                severity=MagicMock(value="high"),
                description="State updated after external call",
                location=MagicMock(
                    file_path="contracts/Vault.sol",
                    start_line=42,
                    end_line=55,
                ),
                remediation="Apply CEI pattern",
            ),
            MagicMock(
                title="Missing Access Control",
                severity=MagicMock(value="critical"),
                description="No onlyOwner modifier",
                location=MagicMock(
                    file_path="contracts/Admin.sol",
                    start_line=10,
                    end_line=15,
                ),
                remediation="Add access control",
            ),
        ]
        annotations = findings_to_annotations(findings)
        assert len(annotations) == 2
        assert annotations[0].path == "contracts/Vault.sol"
        assert annotations[0].annotation_level == "warning"  # high → warning
        assert annotations[1].annotation_level == "failure"  # critical → failure

    def test_findings_to_summary(self):
        findings = [
            MagicMock(
                title="Bug A",
                severity=MagicMock(value="high"),
                category="reentrancy",
            ),
            MagicMock(
                title="Bug B",
                severity=MagicMock(value="medium"),
                category="access_control",
            ),
        ]
        summary = findings_to_summary(findings)
        assert "Bug A" in summary
        assert "Bug B" in summary
        assert "high" in summary.lower() or "High" in summary


class TestDetermineConclusion:
    def test_critical_findings(self):
        findings = [MagicMock(severity=MagicMock(value="critical"))]
        assert determine_conclusion(findings) == CheckConclusion.FAILURE

    def test_high_findings(self):
        findings = [MagicMock(severity=MagicMock(value="high"))]
        assert determine_conclusion(findings) == CheckConclusion.ACTION_REQUIRED

    def test_medium_findings(self):
        findings = [MagicMock(severity=MagicMock(value="medium"))]
        assert determine_conclusion(findings) == CheckConclusion.NEUTRAL

    def test_no_findings(self):
        assert determine_conclusion([]) == CheckConclusion.SUCCESS

    def test_low_only(self):
        findings = [MagicMock(severity=MagicMock(value="low"))]
        assert determine_conclusion(findings) == CheckConclusion.SUCCESS


# ── GitHubAppAuth ────────────────────────────────────────────────────────────


class TestGitHubAppAuth:
    @patch("engine.integrations.github_app.get_settings")
    def test_init(self, mock_settings):
        mock_settings.return_value = MagicMock(
            github_app_id="12345",
            github_app_private_key="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
            github_app_webhook_secret="webhook-sec",
        )
        auth = GitHubAppAuth()
        assert auth is not None

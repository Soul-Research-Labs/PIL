"""Webhook handlers — GitHub, GitLab, and Bitbucket."""

from __future__ import annotations

import hmac
import hashlib
import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request

from engine.core.config import get_settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None),
) -> dict[str, str]:
    """Handle incoming GitHub webhooks (push, pull_request, installation)."""
    settings = get_settings()
    body = await request.body()

    # Verify webhook signature (REQUIRED — reject if no secret configured)
    if not settings.github_webhook_secret:
        raise HTTPException(
            status_code=503,
            detail="Webhook verification not configured — set ZASEON_GITHUB_WEBHOOK_SECRET",
        )

    if not x_hub_signature_256:
        raise HTTPException(status_code=401, detail="Missing signature")

    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Dispatch based on event type
    event = x_github_event or "unknown"

    if event == "push":
        payload_data = json.loads(body)
        # Dispatch scan for the pushed branch
        from engine.pipeline.tasks import run_scan

        branch = payload_data.get("ref", "").replace("refs/heads/", "")
        commit_sha = payload_data.get("after", "")
        repo_url = payload_data.get("repository", {}).get("clone_url", "")
        if repo_url:
            run_scan.delay("", "", {
                "source_type": "github",
                "github_url": repo_url,
                "branch": branch,
                "commit_sha": commit_sha,
                "trigger": "webhook_push",
            })
        return {"status": "accepted", "event": "push"}

    elif event == "pull_request":
        payload_data = json.loads(body)
        action = payload_data.get("action", "")
        if action in ("opened", "synchronize"):
            from engine.pipeline.tasks import run_scan

            pr = payload_data.get("pull_request", {})
            repo_url = payload_data.get("repository", {}).get("clone_url", "")
            if repo_url:
                run_scan.delay("", "", {
                    "source_type": "github",
                    "github_url": repo_url,
                    "branch": pr.get("head", {}).get("ref", ""),
                    "commit_sha": pr.get("head", {}).get("sha", ""),
                    "pr_number": payload_data.get("number"),
                    "trigger": "webhook_pr",
                })
        return {"status": "accepted", "event": "pull_request"}

    elif event == "installation":
        # Log installation events for audit trail
        import logging
        logging.getLogger(__name__).info("GitHub App installation event received")
        return {"status": "accepted", "event": "installation"}

    return {"status": "ignored", "event": event}


# ── Unified multi-SCM webhook endpoint ───────────────────────────────────────


@router.post("/incoming")
async def unified_webhook(request: Request) -> dict[str, str]:
    """Auto-detect SCM provider and handle webhook events.

    Supports GitHub, GitLab, and Bitbucket webhooks through a single endpoint.
    """
    from engine.integrations.scm import detect_provider, get_adapter, WebhookEventType
    from engine.pipeline.tasks import run_scan

    body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}
    settings = get_settings()

    try:
        provider = detect_provider(headers)
    except ValueError:
        raise HTTPException(status_code=400, detail="Cannot detect SCM provider from headers")

    adapter = get_adapter(provider)

    # Verify webhook signature (REQUIRED — reject if no secret configured)
    sig = (
        headers.get("x-hub-signature-256", "")
        or headers.get("x-gitlab-token", "")
        or ""
    )
    secret = settings.github_webhook_secret or ""
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="Webhook verification not configured — set ZASEON_GITHUB_WEBHOOK_SECRET",
        )
    if not adapter.verify_webhook(body, sig, secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = json.loads(body)
    event = adapter.parse_event(headers, payload)

    logger.info(
        "Incoming %s webhook: %s event for %s",
        event.provider.value,
        event.event_type.value,
        event.repo_url,
    )

    if event.event_type in (
        WebhookEventType.PUSH,
        WebhookEventType.PULL_REQUEST,
        WebhookEventType.MERGE_REQUEST,
    ):
        config = {
            "source_type": event.provider.value,
            "github_url": event.clone_url,
            "branch": event.ref,
            "commit_sha": event.commit_sha,
            "trigger": f"webhook_{event.event_type.value}",
        }
        if event.pr_number:
            config["pr_number"] = event.pr_number
        run_scan.delay("", "", config)
        return {"status": "accepted", "provider": event.provider.value, "event": event.event_type.value}

    return {"status": "ignored", "provider": event.provider.value, "event": event.event_type.value}

"""Notification webhook management API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from engine.api.middleware.auth import get_current_user
from engine.api.services.notifications import (
    NotificationChannel,
    NotificationEvent,
    NotificationPayload,
    WebhookConfig,
    notification_service,
)
from engine.models.user import User

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class WebhookCreate(BaseModel):
    """Create a new webhook configuration."""
    channel: NotificationChannel
    webhook_url: str = Field(..., min_length=1)
    events: list[NotificationEvent] = Field(default_factory=list)
    project_id: str = ""
    slack_channel: str = ""
    pagerduty_routing_key: str = ""
    discord_username: str = "PIL++ Bot"
    discord_avatar_url: str = ""


class WebhookResponse(BaseModel):
    id: str
    channel: str
    webhook_url: str
    events: list[str]
    enabled: bool
    project_id: str


class WebhookUpdate(BaseModel):
    """Update webhook configuration."""
    webhook_url: str | None = None
    events: list[NotificationEvent] | None = None
    enabled: bool | None = None
    slack_channel: str | None = None


class TestNotificationRequest(BaseModel):
    event: NotificationEvent = NotificationEvent.SCAN_COMPLETED


class TestNotificationResponse(BaseModel):
    results: dict[str, bool]


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/", response_model=list[WebhookResponse])
async def list_webhooks(project_id: str = "", user: User = Depends(get_current_user)) -> list[WebhookResponse]:
    """List all registered webhooks."""
    configs = notification_service.list_webhooks(project_id=project_id)
    return [
        WebhookResponse(
            id=c.id,
            channel=c.channel.value,
            webhook_url=_mask_url(c.webhook_url),
            events=[e.value for e in c.events],
            enabled=c.enabled,
            project_id=c.project_id,
        )
        for c in configs
    ]


@router.post("/", response_model=WebhookResponse, status_code=201)
async def create_webhook(body: WebhookCreate, user: User = Depends(get_current_user)) -> WebhookResponse:
    """Register a new webhook."""
    config = WebhookConfig(
        id=str(uuid.uuid4()),
        channel=body.channel,
        webhook_url=body.webhook_url,
        events=body.events,
        project_id=body.project_id,
        slack_channel=body.slack_channel,
        pagerduty_routing_key=body.pagerduty_routing_key,
        discord_username=body.discord_username,
        discord_avatar_url=body.discord_avatar_url,
    )
    notification_service.register(config)
    return WebhookResponse(
        id=config.id,
        channel=config.channel.value,
        webhook_url=_mask_url(config.webhook_url),
        events=[e.value for e in config.events],
        enabled=config.enabled,
        project_id=config.project_id,
    )


@router.patch("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(webhook_id: str, body: WebhookUpdate, user: User = Depends(get_current_user)) -> WebhookResponse:
    """Update a webhook configuration."""
    configs = notification_service.list_webhooks()
    config = next((c for c in configs if c.id == webhook_id), None)
    if not config:
        raise HTTPException(status_code=404, detail="Webhook not found")

    if body.webhook_url is not None:
        config.webhook_url = body.webhook_url
    if body.events is not None:
        config.events = body.events
    if body.enabled is not None:
        config.enabled = body.enabled
    if body.slack_channel is not None:
        config.slack_channel = body.slack_channel

    return WebhookResponse(
        id=config.id,
        channel=config.channel.value,
        webhook_url=_mask_url(config.webhook_url),
        events=[e.value for e in config.events],
        enabled=config.enabled,
        project_id=config.project_id,
    )


@router.delete("/{webhook_id}")
async def delete_webhook(webhook_id: str, user: User = Depends(get_current_user)) -> dict[str, str]:
    """Delete a webhook."""
    if not notification_service.unregister(webhook_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"status": "deleted", "id": webhook_id}


@router.post("/{webhook_id}/test", response_model=TestNotificationResponse)
async def test_webhook(webhook_id: str, body: TestNotificationRequest, user: User = Depends(get_current_user)) -> TestNotificationResponse:
    """Send a test notification to a specific webhook."""
    configs = notification_service.list_webhooks()
    config = next((c for c in configs if c.id == webhook_id), None)
    if not config:
        raise HTTPException(status_code=404, detail="Webhook not found")

    payload = NotificationPayload(
        event=body.event,
        title="Test Notification from PIL++",
        description="This is a test notification to verify your webhook configuration.",
        severity="info",
        fields={"Type": "Test", "Source": "PIL++ Dashboard"},
    )

    # Temporarily send to just this webhook
    from engine.api.services.notifications import BaseNotifier, NotificationService
    notifier_cls = NotificationService._NOTIFIER_MAP.get(config.channel)
    if not notifier_cls:
        raise HTTPException(status_code=400, detail=f"Unknown channel: {config.channel}")

    notifier = notifier_cls(config)
    success = await notifier.send(payload)
    return TestNotificationResponse(results={webhook_id: success})


# ── Helpers ──────────────────────────────────────────────────────────────────


def _mask_url(url: str) -> str:
    """Mask webhook URL for display (show first and last 8 chars)."""
    if len(url) <= 20:
        return url
    return url[:12] + "****" + url[-8:]

"""Notification / webhook integrations — Slack, Discord, PagerDuty.

Sends scan results, finding alerts, and campaign status updates to
external services. Configurable per-project via the notifications API.

Architecture
------------
::

    NotificationService
      ├── SlackNotifier    → Slack Incoming Webhook / Bot
      ├── DiscordNotifier  → Discord Webhook
      └── PagerDutyNotifier→ PagerDuty Events API v2
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────────────


class NotificationChannel(str, Enum):
    SLACK = "slack"
    DISCORD = "discord"
    PAGERDUTY = "pagerduty"


class NotificationEvent(str, Enum):
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    FINDING_CRITICAL = "finding.critical"
    FINDING_HIGH = "finding.high"
    CAMPAIGN_STARTED = "campaign.started"
    CAMPAIGN_COMPLETED = "campaign.completed"
    CAMPAIGN_VIOLATION = "campaign.violation"


@dataclass
class WebhookConfig:
    """Configuration for a single webhook destination."""
    id: str
    channel: NotificationChannel
    webhook_url: str
    events: list[NotificationEvent] = field(default_factory=list)
    enabled: bool = True
    project_id: str = ""
    # Channel-specific
    slack_channel: str = ""       # Override channel (Slack bot only)
    pagerduty_routing_key: str = ""
    discord_username: str = "PIL++ Bot"
    discord_avatar_url: str = ""


@dataclass
class NotificationPayload:
    """Normalized notification payload."""
    event: NotificationEvent
    title: str
    description: str
    severity: str = "info"  # info, warning, critical
    url: str = ""           # Link to finding/scan/campaign in dashboard
    fields: dict[str, str] = field(default_factory=dict)
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.time()


# ── Base Notifier ────────────────────────────────────────────────────────────


class BaseNotifier:
    """Abstract base for notification channel implementations."""

    CHANNEL: NotificationChannel

    def __init__(self, config: WebhookConfig) -> None:
        self._config = config

    async def send(self, payload: NotificationPayload) -> bool:
        """Send a notification. Returns True on success."""
        raise NotImplementedError

    def _should_send(self, event: NotificationEvent) -> bool:
        """Check if this webhook should handle this event type."""
        if not self._config.enabled:
            return False
        if self._config.events and event not in self._config.events:
            return False
        return True


# ── Slack ─────────────────────────────────────────────────────────────────────


class SlackNotifier(BaseNotifier):
    """Send notifications to Slack via Incoming Webhook."""

    CHANNEL = NotificationChannel.SLACK

    SEVERITY_COLORS = {
        "critical": "#dc2626",  # red-600
        "warning": "#f59e0b",   # amber-500
        "info": "#3b82f6",      # blue-500
    }

    SEVERITY_EMOJI = {
        "critical": ":rotating_light:",
        "warning": ":warning:",
        "info": ":information_source:",
    }

    async def send(self, payload: NotificationPayload) -> bool:
        if not self._should_send(payload.event):
            return False

        color = self.SEVERITY_COLORS.get(payload.severity, "#6b7280")
        emoji = self.SEVERITY_EMOJI.get(payload.severity, ":bell:")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {payload.title}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": payload.description,
                },
            },
        ]

        if payload.fields:
            field_blocks = [
                {"type": "mrkdwn", "text": f"*{k}*\n{v}"}
                for k, v in list(payload.fields.items())[:10]
            ]
            blocks.append({"type": "section", "fields": field_blocks})

        if payload.url:
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in Dashboard"},
                    "url": payload.url,
                    "style": "primary",
                }],
            })

        slack_payload = {
            "attachments": [{
                "color": color,
                "blocks": blocks,
            }],
        }
        if self._config.slack_channel:
            slack_payload["channel"] = self._config.slack_channel

        return await self._post(slack_payload)

    async def _post(self, body: dict) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self._config.webhook_url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    return True
                logger.warning("Slack webhook returned %d: %s", resp.status_code, resp.text)
        except Exception as exc:
            logger.warning("Slack notification failed: %s", exc)
        return False


# ── Discord ──────────────────────────────────────────────────────────────────


class DiscordNotifier(BaseNotifier):
    """Send notifications to Discord via webhook."""

    CHANNEL = NotificationChannel.DISCORD

    SEVERITY_COLORS = {
        "critical": 0xDC2626,
        "warning": 0xF59E0B,
        "info": 0x3B82F6,
    }

    async def send(self, payload: NotificationPayload) -> bool:
        if not self._should_send(payload.event):
            return False

        color = self.SEVERITY_COLORS.get(payload.severity, 0x6B7280)

        embed = {
            "title": payload.title,
            "description": payload.description[:4096],
            "color": color,
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(payload.timestamp)
            ),
            "footer": {"text": "PIL++ Security Scanner"},
        }

        if payload.fields:
            embed["fields"] = [
                {"name": k, "value": v[:1024], "inline": True}
                for k, v in list(payload.fields.items())[:25]
            ]

        if payload.url:
            embed["url"] = payload.url

        discord_payload: dict[str, Any] = {"embeds": [embed]}
        if self._config.discord_username:
            discord_payload["username"] = self._config.discord_username
        if self._config.discord_avatar_url:
            discord_payload["avatar_url"] = self._config.discord_avatar_url

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self._config.webhook_url,
                    json=discord_payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code in (200, 204):
                    return True
                logger.warning("Discord webhook returned %d: %s", resp.status_code, resp.text)
        except Exception as exc:
            logger.warning("Discord notification failed: %s", exc)
        return False


# ── PagerDuty ────────────────────────────────────────────────────────────────


class PagerDutyNotifier(BaseNotifier):
    """Send alerts to PagerDuty via Events API v2."""

    CHANNEL = NotificationChannel.PAGERDUTY
    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    SEVERITY_MAP = {
        "critical": "critical",
        "warning": "warning",
        "info": "info",
    }

    async def send(self, payload: NotificationPayload) -> bool:
        if not self._should_send(payload.event):
            return False

        routing_key = self._config.pagerduty_routing_key or self._config.webhook_url
        severity = self.SEVERITY_MAP.get(payload.severity, "info")

        # Only trigger PagerDuty for critical/warning events
        if severity == "info":
            return True  # silently skip low-severity

        dedup_key = hashlib.sha256(
            f"{payload.event.value}:{payload.title}".encode()
        ).hexdigest()[:32]

        pd_payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": f"[PIL++] {payload.title}",
                "source": "pil-plus-plus",
                "severity": severity,
                "component": "security-scanner",
                "custom_details": {
                    "description": payload.description,
                    "event": payload.event.value,
                    **payload.fields,
                },
            },
        }

        if payload.url:
            pd_payload["links"] = [{"href": payload.url, "text": "View in Dashboard"}]

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self.EVENTS_URL,
                    json=pd_payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 202:
                    return True
                logger.warning("PagerDuty API returned %d: %s", resp.status_code, resp.text)
        except Exception as exc:
            logger.warning("PagerDuty notification failed: %s", exc)
        return False


# ── Notification Service ─────────────────────────────────────────────────────


class NotificationService:
    """Manages webhook configs and dispatches notifications."""

    _NOTIFIER_MAP: dict[NotificationChannel, type[BaseNotifier]] = {
        NotificationChannel.SLACK: SlackNotifier,
        NotificationChannel.DISCORD: DiscordNotifier,
        NotificationChannel.PAGERDUTY: PagerDutyNotifier,
    }

    def __init__(self) -> None:
        self._configs: dict[str, WebhookConfig] = {}

    def register(self, config: WebhookConfig) -> None:
        """Register a webhook configuration."""
        self._configs[config.id] = config
        logger.info("Registered %s webhook %s", config.channel.value, config.id)

    def unregister(self, webhook_id: str) -> bool:
        """Unregister a webhook."""
        return self._configs.pop(webhook_id, None) is not None

    def list_webhooks(self, project_id: str = "") -> list[WebhookConfig]:
        """List all webhooks, optionally filtered by project."""
        configs = list(self._configs.values())
        if project_id:
            configs = [c for c in configs if c.project_id == project_id]
        return configs

    async def notify(self, payload: NotificationPayload) -> dict[str, bool]:
        """Dispatch notification to all matching webhooks.

        Returns dict of webhook_id → success.
        """
        results: dict[str, bool] = {}
        tasks: list[tuple[str, asyncio.Task]] = []

        for config in self._configs.values():
            if not config.enabled:
                continue
            if config.events and payload.event not in config.events:
                continue

            notifier_cls = self._NOTIFIER_MAP.get(config.channel)
            if not notifier_cls:
                continue

            notifier = notifier_cls(config)
            tasks.append((config.id, asyncio.create_task(notifier.send(payload))))

        for config_id, task in tasks:
            try:
                results[config_id] = await task
            except Exception as exc:
                logger.warning("Notification %s failed: %s", config_id, exc)
                results[config_id] = False

        return results

    async def notify_scan_completed(
        self,
        scan_id: str,
        project_name: str,
        findings_count: int,
        critical_count: int,
        score: float,
        dashboard_url: str = "",
    ) -> dict[str, bool]:
        """Convenience: notify about scan completion."""
        severity = "critical" if critical_count > 0 else "warning" if findings_count > 0 else "info"
        return await self.notify(NotificationPayload(
            event=NotificationEvent.SCAN_COMPLETED,
            title=f"Scan completed: {project_name}",
            description=(
                f"Security scan finished with **{findings_count}** findings "
                f"({critical_count} critical). Security score: **{score:.0f}/100**"
            ),
            severity=severity,
            url=f"{dashboard_url}/scans/{scan_id}" if dashboard_url else "",
            fields={
                "Findings": str(findings_count),
                "Critical": str(critical_count),
                "Score": f"{score:.0f}/100",
            },
        ))

    async def notify_critical_finding(
        self,
        finding_title: str,
        finding_description: str,
        scan_id: str,
        finding_id: str,
        dashboard_url: str = "",
    ) -> dict[str, bool]:
        """Convenience: notify about a critical finding."""
        return await self.notify(NotificationPayload(
            event=NotificationEvent.FINDING_CRITICAL,
            title=f"Critical Finding: {finding_title}",
            description=finding_description[:2000],
            severity="critical",
            url=f"{dashboard_url}/findings/{finding_id}" if dashboard_url else "",
            fields={"Scan ID": scan_id, "Finding ID": finding_id},
        ))


# ── Global singleton ─────────────────────────────────────────────────────────

notification_service = NotificationService()

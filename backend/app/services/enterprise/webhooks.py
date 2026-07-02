"""Webhook notification service for security assessment events.

Sends POST notifications on configurable events:
  - scan.completed
  - finding.critical
  - finding.new

Disabled by default — enable via webhook_url setting.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class WebhookEvent(str, Enum):
    SCAN_COMPLETED = "scan.completed"
    FINDING_CRITICAL = "finding.critical"
    FINDING_NEW = "finding.new"
    SCAN_FAILED = "scan.failed"


class WebhookNotifier:
    """Sends webhook notifications for scan events.

    Disabled when webhook_url is not configured.
    """

    def __init__(self, webhook_url: str | None = None):
        self._url = webhook_url or os.environ.get("WEBHOOK_URL", "")
        self._enabled = bool(self._url and self._url.startswith("http"))

    def send(self, event: WebhookEvent, payload: dict[str, Any]) -> bool:
        """Send a webhook notification. Returns True if sent successfully."""
        if not self._enabled:
            logger.debug("WEBHOOK: disabled, skipping %s event", event.value)
            return False

        body = {
            "event": event.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        }

        try:
            async def _send():
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(self._url, json=body)
                    resp.raise_for_status()
                    return True
            return asyncio.run(_send())
        except Exception as exc:
            logger.warning("WEBHOOK: failed to send %s: %s", event.value, exc)
            return False

    def notify_scan_completed(self, scan_id: str, target_url: str, risk_score: float,
                               findings_count: int) -> None:
        self.send(WebhookEvent.SCAN_COMPLETED, {
            "scan_id": scan_id,
            "target_url": target_url,
            "risk_score": risk_score,
            "findings_count": findings_count,
        })

    def notify_critical_finding(self, scan_id: str, finding: dict) -> None:
        self.send(WebhookEvent.FINDING_CRITICAL, {
            "scan_id": scan_id,
            "finding_title": finding.get("title", ""),
            "severity": finding.get("severity", "critical"),
            "cvss_score": finding.get("cvss_score"),
            "detail": (finding.get("detail") or "")[:500],
        })

    def notify_scan_failed(self, scan_id: str, error: str) -> None:
        self.send(WebhookEvent.SCAN_FAILED, {
            "scan_id": scan_id,
            "error": error[:1000],
        })

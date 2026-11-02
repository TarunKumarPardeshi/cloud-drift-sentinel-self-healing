"""Slack notification formatter and webhook dispatcher."""

import json
import logging
from typing import Dict, Any, Optional
import httpx

logger = logging.getLogger("drift.slack")


class SlackNotifier:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url

    def build_alert_payload(
        self,
        event_name: str,
        user_identity: str,
        resource_id: str,
        region: str,
        remediation_action: str,
        status: str = "AUTO-REMEDIATED"
    ) -> Dict[str, Any]:
        """Constructs a Slack Block Kit security alert payload."""
        return {
            "text": f"🚨 Cloud Security Drift Intercepted: {event_name}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 Cloud Security Drift Intercepted & Healed",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Event API:*\n`{event_name}`"},
                        {"type": "mrkdwn", "text": f"*Offending Principal:*\n`{user_identity}`"},
                        {"type": "mrkdwn", "text": f"*Target Resource:*\n`{resource_id}`"},
                        {"type": "mrkdwn", "text": f"*Region:*\n`{region}`"}
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Self-Healing Action Executed:*\n```{remediation_action}```\n*Status:* `COMPLIANCE RESTORED ✅`"
                    }
                }
            ]
        }

    async def send_alert(self, payload: Dict[str, Any]) -> bool:
        if not self.webhook_url:
            logger.info("Slack webhook not configured; alert printed to log.")
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(self.webhook_url, json=payload)
                return resp.status_code == 200
        except Exception as e:
            logger.error(f"Failed to post Slack alert: {e}")
            return False

"""Generic webhook alert delivery (Slack, MS Teams, PagerDuty, Zapier, …).

If ALERT_WEBHOOK_URL is set in the environment, every critical/high alert is
POSTed to that URL in a Slack-compatible JSON shape. Missing URL = silent
no-op, so the demo path stays green.
"""
from __future__ import annotations

import httpx

from app.config import settings
from app.schemas import AlertEvent


def _severity_color(severity: str) -> str:
    return {
        "critical": "#e11d48",
        "high": "#f97316",
        "medium": "#f59e0b",
        "low": "#0ea5e9",
    }.get(severity, "#64748b")


def _payload(event: AlertEvent) -> dict:
    body = (
        f"*VendorGuard AI alert — {event.severity.upper()}*\n"
        f"*Vendor:* `{event.vendor}`\n"
        f"*{event.title}*\n"
        f"{event.summary}\n"
        f"*Action:* {event.action_taken}\n"
        f"*DPDP exposure:* ₹{event.dpdp_exposure_inr / 1e7:.1f} Cr\n"
        f"*Contained in:* {event.containment_seconds}s"
    )
    return {
        "text": body,
        "attachments": [
            {
                "color": _severity_color(event.severity),
                "fallback": event.title,
                "title": event.title,
                "text": body,
                "footer": f"alert={event.id} · anomaly_score={event.anomaly_score}",
            }
        ],
    }


async def fire(event: AlertEvent) -> dict:
    url = settings.alert_webhook_url
    if not url:
        return {"channel": "webhook", "status": "skipped", "reason": "no webhook configured"}
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.post(url, json=_payload(event))
            return {
                "channel": "webhook",
                "status": "sent" if r.status_code < 300 else "error",
                "http_status": r.status_code,
                "url_host": url.split("/")[2] if "//" in url else url,
            }
    except Exception as e:
        return {"channel": "webhook", "status": "error", "error": str(e)}

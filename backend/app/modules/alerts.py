"""Alerting module: WhatsApp via Twilio if configured, console always, plus
in-process SSE fan-out so the dashboard lights up in real time."""
from __future__ import annotations

from rich.console import Console

from app.config import settings
from app.modules import events, store, webhook
from app.schemas import AlertEvent

console = Console()


def _format_whatsapp(event: AlertEvent) -> str:
    return (
        f"🚨 *VendorGuard Alert* 🚨\n\n"
        f"Vendor: *{event.vendor}*\n"
        f"Severity: *{event.severity.upper()}*\n"
        f"{event.title}\n\n"
        f"{event.summary}\n\n"
        f"{event.action_taken}\n\n"
        f"DPDP Exposure: ₹{event.dpdp_exposure_inr / 1e7:.0f} Cr\n"
        f"Contained in: *{event.containment_seconds}s*"
    )


async def dispatch(event: AlertEvent) -> dict:
    body = _format_whatsapp(event)
    console.rule(f"[bold red]ALERT {event.id}")
    console.print(body)

    # Persist + fan out to any live SSE subscribers
    await store.save_alert(event.model_dump())
    events.publish("alerts", event.model_dump())

    # Fire generic webhook (Slack/Teams/Zapier) if configured — best-effort.
    webhook_result = await webhook.fire(event)

    if not (settings.has_twilio and settings.alert_whatsapp_to):
        return {"channel": "console", "status": "logged", "body": body, "webhook": webhook_result}

    try:
        from twilio.rest import Client

        client = Client(settings.twilio_account_sid, settings.twilio_auth_token)
        msg = client.messages.create(
            from_=settings.twilio_whatsapp_from,
            to=settings.alert_whatsapp_to,
            body=body,
        )
        return {"channel": "whatsapp", "status": "sent", "sid": msg.sid, "webhook": webhook_result}
    except Exception as e:
        console.print(f"[yellow]Twilio send failed, falling back to console: {e}")
        return {"channel": "console", "status": "fallback", "error": str(e), "body": body, "webhook": webhook_result}

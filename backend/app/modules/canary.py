"""Canary tokens — trip-wires for compromised vendor credentials.

Inspired by Thinkst Canary / OpenCanary. A canary token is an innocuous-looking
endpoint (e.g. `/reporting/export-legacy`) that no legitimate vendor traffic
should ever hit. If it *is* hit, we have an almost-zero-false-positive signal
that the vendor token is being misused.

This complements VendorGuard's anomaly engine:
- Anomaly engine catches *statistical* outliers in legitimate-looking traffic.
- Canary tokens catch attackers who probe endpoints they were never told exist.

This is also how we absorb the 'honeypot' narrative competitors might pitch:
canaries are a layer *inside* VendorGuard, not the whole product.
"""
from __future__ import annotations

import time
import uuid

from app.modules import store
from app.schemas import CanaryToken


async def mint(vendor: str, endpoint: str) -> CanaryToken:
    tok = CanaryToken(
        id=f"cnr-{uuid.uuid4().hex[:10]}",
        vendor=vendor,
        endpoint=endpoint,
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    await store.save_canary(tok.model_dump())
    return tok


async def trip(token_id: str, from_ip: str) -> CanaryToken | None:
    row = await store.load_canary(token_id)
    if not row:
        return None
    row["triggered"] = True
    row["triggered_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    row["triggered_from"] = from_ip
    await store.save_canary(row)
    return CanaryToken.model_validate(row)


async def list_for(vendor: str | None = None) -> list[CanaryToken]:
    rows = await store.list_canaries(vendor)
    return [CanaryToken.model_validate(r) for r in rows]

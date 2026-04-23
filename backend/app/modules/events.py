"""In-process pub/sub for server-sent events.

Any module can call `publish(channel, payload)` and subscribers on the HTTP
side receive it via an async queue. Used by the SSE /alerts/stream endpoint so
the dashboard updates without polling.
"""
from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from typing import Any

_subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)


def subscribe(channel: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=256)
    _subscribers[channel].add(q)
    return q


def unsubscribe(channel: str, q: asyncio.Queue) -> None:
    _subscribers[channel].discard(q)


def publish(channel: str, payload: Any) -> None:
    """Non-blocking fan-out. Drops to slowest subscribers if queue is full."""
    body = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    for q in list(_subscribers.get(channel, ())):
        try:
            q.put_nowait(body)
        except asyncio.QueueFull:
            # Slow consumer — drop rather than block the producer.
            pass


def subscriber_count(channel: str) -> int:
    return len(_subscribers.get(channel, ()))

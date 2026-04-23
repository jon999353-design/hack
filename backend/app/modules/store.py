"""SQLite-backed persistence for scans, gateway state and alerts.

Swaps out the original in-RAM dict so the dashboard, history and report
endpoints all survive restarts. Uses `aiosqlite` (already in requirements)
for async-safe access from the FastAPI event loop.
"""
from __future__ import annotations

import json
import time
from typing import Any

import aiosqlite

from app.config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    vendor TEXT PRIMARY KEY,
    scanned_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    score INTEGER,
    band TEXT,
    exposure_inr INTEGER,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    at TEXT NOT NULL,
    severity TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_state (
    vendor TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS canary_tokens (
    id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_vendor ON alerts(vendor);
CREATE INDEX IF NOT EXISTS idx_alerts_at ON alerts(at);
CREATE INDEX IF NOT EXISTS idx_scan_history_vendor ON scan_history(vendor, scanned_at);
"""


async def init_db() -> None:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        await db.executescript(_SCHEMA)
        await db.commit()


# ------------------------------------------------------------------ scans
async def save_scan(vendor: str, result: dict[str, Any]) -> None:
    blob = json.dumps(result)
    score = (result.get("trust") or {}).get("score")
    band = (result.get("trust") or {}).get("band")
    exposure = int(result.get("total_dpdp_exposure_inr") or 0)
    scanned_at = result.get("scanned_at", "")
    async with aiosqlite.connect(settings.sqlite_path) as db:
        await db.execute(
            "INSERT INTO scans(vendor, scanned_at, data) VALUES(?,?,?) "
            "ON CONFLICT(vendor) DO UPDATE SET scanned_at=excluded.scanned_at, data=excluded.data",
            (vendor, scanned_at, blob),
        )
        await db.execute(
            "INSERT INTO scan_history(vendor, scanned_at, score, band, exposure_inr, data) "
            "VALUES(?,?,?,?,?,?)",
            (vendor, scanned_at, score, band, exposure, blob),
        )
        await db.commit()


async def scan_history(vendor: str, limit: int = 20) -> list[dict]:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        cur = await db.execute(
            "SELECT id, scanned_at, score, band, exposure_inr FROM scan_history "
            "WHERE vendor=? ORDER BY id DESC LIMIT ?",
            (vendor, limit),
        )
        rows = await cur.fetchall()
    return [
        {
            "id": r[0],
            "scanned_at": r[1],
            "score": r[2],
            "band": r[3],
            "exposure_inr": r[4],
        }
        for r in rows
    ]


async def scan_by_id(scan_id: int) -> dict | None:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        cur = await db.execute(
            "SELECT vendor, scanned_at, data FROM scan_history WHERE id=?", (scan_id,)
        )
        row = await cur.fetchone()
    if not row:
        return None
    return json.loads(row[2])


async def load_scan(vendor: str) -> dict | None:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        cur = await db.execute("SELECT data FROM scans WHERE vendor=?", (vendor,))
        row = await cur.fetchone()
    return json.loads(row[0]) if row else None


async def list_vendors() -> list[dict]:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        cur = await db.execute("SELECT vendor, data FROM scans ORDER BY scanned_at DESC")
        rows = await cur.fetchall()
    out = []
    for vendor, data_json in rows:
        data = json.loads(data_json)
        out.append({
            "vendor": vendor,
            "score": data.get("trust", {}).get("score"),
            "band": data.get("trust", {}).get("band"),
            "scanned_at": data.get("scanned_at"),
            "exposure_inr": data.get("total_dpdp_exposure_inr"),
        })
    return out


# ------------------------------------------------------------------ alerts
async def save_alert(event: dict[str, Any]) -> None:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        await db.execute(
            "INSERT OR REPLACE INTO alerts(id, vendor, at, severity, data) VALUES(?,?,?,?,?)",
            (event["id"], event["vendor"], event["at"], event["severity"], json.dumps(event)),
        )
        await db.commit()


async def recent_alerts(limit: int = 50) -> list[dict]:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        cur = await db.execute(
            "SELECT data FROM alerts ORDER BY at DESC LIMIT ?", (limit,)
        )
        rows = await cur.fetchall()
    return [json.loads(r[0]) for r in rows]


# ------------------------------------------------------------------ gateway state
async def save_gateway(vendor: str, state: dict[str, Any]) -> None:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        await db.execute(
            "INSERT INTO gateway_state(vendor, data, updated_at) VALUES(?,?,?) "
            "ON CONFLICT(vendor) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
            (vendor, json.dumps(state), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        await db.commit()


async def load_gateway(vendor: str) -> dict | None:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        cur = await db.execute("SELECT data FROM gateway_state WHERE vendor=?", (vendor,))
        row = await cur.fetchone()
    return json.loads(row[0]) if row else None


# ------------------------------------------------------------------ canaries
async def save_canary(token: dict[str, Any]) -> None:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        await db.execute(
            "INSERT OR REPLACE INTO canary_tokens(id, vendor, data) VALUES(?,?,?)",
            (token["id"], token["vendor"], json.dumps(token)),
        )
        await db.commit()


async def load_canary(token_id: str) -> dict | None:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        cur = await db.execute("SELECT data FROM canary_tokens WHERE id=?", (token_id,))
        row = await cur.fetchone()
    return json.loads(row[0]) if row else None


async def list_canaries(vendor: str | None = None) -> list[dict]:
    async with aiosqlite.connect(settings.sqlite_path) as db:
        if vendor:
            cur = await db.execute(
                "SELECT data FROM canary_tokens WHERE vendor=?", (vendor,)
            )
        else:
            cur = await db.execute("SELECT data FROM canary_tokens")
        rows = await cur.fetchall()
    return [json.loads(r[0]) for r in rows]

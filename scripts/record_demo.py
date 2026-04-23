#!/usr/bin/env python3
"""Drive the VendorGuard AI frontend through its Demo Mode script via
Playwright and record a WebM video of the run.

Assumes:
- backend is running at http://127.0.0.1:8765 (DEMO_MODE=true)
- frontend is served at http://127.0.0.1:5173/index.html

Produces:
- out/demo-walkthrough.webm  (viewport capture from Playwright)

Usage:
    python scripts/record_demo.py
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from playwright.async_api import async_playwright

REPO = Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "out"
OUT_WEBM = OUT_DIR / "demo-walkthrough.webm"

FRONTEND_URL = "http://127.0.0.1:5173/index.html?api=http://127.0.0.1:8765"

# Panels to visit after Demo Mode fires. Matches the sidebar data-view attrs
# defined in frontend/index.html.
# Dwells scaled so the walkthrough lines up with the ~3-minute Sarvam voiceover.
# Panel ids match the v3.x NAV_ITEMS / navTo() graph in frontend/index.html.
PANELS: list[tuple[str, float]] = [
    ("executive", 14.0),
    ("overview", 14.0),
    ("findings", 16.0),
    ("dpdp", 22.0),
    ("contract", 14.0),
    ("gateway", 18.0),
    ("playbook", 12.0),
    ("report", 14.0),
]


async def run() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            record_video_dir=str(OUT_DIR),
            record_video_size={"width": 1440, "height": 900},
        )
        page = await context.new_page()
        await page.goto(FRONTEND_URL, wait_until="domcontentloaded", timeout=15000)
        await page.wait_for_timeout(2500)

        # Hide the api-status chip — on some layouts it intercepts pointer
        # events for the top-bar scan button and the first sidebar button.
        await page.evaluate(
            "() => { const el = document.getElementById('api-status');"
            " if (el) el.style.pointerEvents = 'none'; }"
        )

        # Step 1: scan paytrust-partner.com so the app is in a real state
        # before Demo Mode starts.
        await page.fill("#vendor-input", "paytrust-partner.com")
        try:
            await page.click("#scan-btn", force=True, timeout=3000)
        except Exception as exc:
            print(f"[record] scan click failed: {exc}")
        await page.wait_for_timeout(3500)
        print("[record] scan fired")

        async def nav_to(panel_id: str, dwell_s: float) -> None:
            # navTo() accepts both top-level nav ids and direct panel ids,
            # which is simpler + more reliable than clicking the sidebar
            # (where the api-status chip occasionally intercepts clicks).
            try:
                await page.evaluate(f"window.navTo && window.navTo('{panel_id}')")
            except Exception:
                pass
            await page.wait_for_timeout(int(dwell_s * 1000))

        # Walk each panel for a fixed dwell time.
        for view, dwell in PANELS:
            await nav_to(view, dwell)

        # Gateway activate + simulate attack, so the live containment timer
        # and alert card render during the gateway dwell.
        await nav_to("gateway", 1.5)
        for btn_text in ("Activate Gateway", "Simulate Attack"):
            btn = page.locator("button", has_text=btn_text).first
            if await btn.count():
                try:
                    await btn.scroll_into_view_if_needed(timeout=1500)
                    await btn.click(timeout=1500, force=True)
                    await page.wait_for_timeout(8000)
                except Exception:
                    pass

        # Ask DPDP — open the Ask drawer and fire the §8(5) preset question so
        # we capture the PR #3 RAG boost fix in the recording. Drawer is a
        # global "Ask DPDP" button in the top bar.
        try:
            await page.evaluate(
                "() => { const b = [...document.querySelectorAll('button')]"
                ".find(x => /ask\\s*dpdp/i.test(x.textContent || ''));"
                " if (b) b.click(); }"
            )
            await page.wait_for_timeout(1200)
            await page.evaluate(
                "() => { if (window.drawerAsk)"
                " window.drawerAsk('What are the penalties under Section 8(5)?'); }"
            )
            await page.wait_for_timeout(14000)
        except Exception:
            pass

        # End on executive board — clean closing shot.
        await nav_to("executive", 10.0)

        video = page.video
        video_path = await video.path() if video else None
        await context.close()
        await browser.close()

        if video_path:
            shutil.move(video_path, OUT_WEBM)
            print(f"[record] wrote {OUT_WEBM} ({OUT_WEBM.stat().st_size:,} bytes)")
        else:
            print("[record] no video captured")


if __name__ == "__main__":
    asyncio.run(run())

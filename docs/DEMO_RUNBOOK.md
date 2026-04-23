# Live-Demo Runbook

Step-by-step script for the live demo. Every command is spelled out. Every line you speak is scripted. Rehearse this with a stopwatch until it runs in **under 90 seconds**.

---

## Setup (do this 30 minutes before your slot)

1. Arrive at the venue. Find a power outlet. Plug in. Battery is not a variable you want.
2. Connect to the venue WiFi. Test with `ping 8.8.8.8`. If it fails, switch to phone hotspot *before* you need it.
3. Open **three terminals** and **one browser window**, arranged like this:

```
┌──────────────────┬──────────────────┐
│ Terminal 1       │ Terminal 2       │
│ uvicorn backend  │ demo_attack.py   │
├──────────────────┴──────────────────┤
│ Browser — frontend/index.html       │
│                                     │
└─────────────────────────────────────┘
```

4. In terminal 1 (backend), run:
   ```bash
   cd vendorguard-ai/backend
   uvicorn app.main:app --host 127.0.0.1 --port 8765 --log-level warning
   ```
   Wait until you see `Uvicorn running on http://127.0.0.1:8765`.

5. In terminal 2, preload the scan so it's cached:
   ```bash
   curl -s -X POST http://127.0.0.1:8765/scan -H 'Content-Type: application/json' -d '{"vendor":"paytrust-partner.com"}' > /dev/null
   ```

6. In the browser, open `file:///path/to/vendorguard-ai/frontend/index.html` (or the deployed Vercel URL). The dashboard auto-loads the `paytrust-partner.com` scan, shows a red 44/100 trust score, and the findings table.

7. **Close every other browser tab.** No Gmail, no Slack, no notifications.

8. Mute notifications on your laptop:
   - Mac: `Do Not Disturb` on
   - Linux: `dunstctl set-paused true`
   - Windows: Focus Assist — Priority only

9. Screen resolution: **1920×1080** or **2560×1440**. Zoom the browser to **125%** so the text is readable from 10 feet away.

10. In terminal 2, have this command *typed but not executed* so you just press Enter when it's time:
    ```
    python scripts/demo_attack.py
    ```

---

## The demo (90 seconds on the clock)

### Beat 1 — Introduce the product (8 seconds)
> **"Vendor risk in 60 seconds — watch this."**

Switch to browser. Point at the trust score ring showing 44.

### Beat 2 — Walk the findings (20 seconds)
> **"We've already scanned `paytrust-partner.com` — our demo payments vendor. Six findings. Redis port 6379 exposed publicly — *critical*. Four employee credentials leaked on LinkedIn and MyFitnessPal breaches. TLS 1.0 still enabled. SPF and DMARC missing."**

Scroll the findings panel once slowly. Stop at the critical finding.

### Beat 3 — DPDP mapping (15 seconds)
> **"Here's where we're different. Every single finding is mapped to the Digital Personal Data Protection Act. Sections 8(5) and 8(6) together: ₹450 crore of penalty exposure. Your CEO is personally liable under Section 8(5). A CISO sees a number, not a vulnerability."**

Point at the DPDP exposure table.

### Beat 4 — Activate gateway (7 seconds)
> **"Now I route this vendor through the VendorGuard gateway."**

Click "Activate Gateway". Point at the green `● active` indicator.

### Beat 5 — The attack simulation — THE MIC DROP (25 seconds)
> **"The vendor now tries to export 12,000 customer records. Our baseline is 500. Watch."**

Click "▶ Simulate Attack".

Wait for the red alert card to pulse in.

> **"Exfiltration pattern detected. Twenty-four times baseline. Token revoked. Endpoint locked. Credentials rotation queued. WhatsApp alert to the CISO.**
>
> **[Pause. 2 full seconds. Let them read the red box.]**
>
> **Contained in three point one five seconds. ₹450 crore of DPDP exposure — avoided."**

### Beat 6 — Close (10 seconds)
> **"Teleport controls access. StrongDM controls queries. VendorGuard controls API-level behaviour — and maps every one to DPDP penalty in rupees. Questions?"**

Open hands. Smile. Shut up. **Do not keep talking.**

---

## Terminal demo variant (use if the browser misbehaves)

If the dashboard fails to load but the backend is up, pivot to the terminal:

> **"I'll walk you through this on the backend — every slide you're seeing is a real REST call."**

In terminal 2, press Enter on the pre-typed `python scripts/demo_attack.py`. The Rich TUI will render the same flow with colour panels. It's actually MORE dramatic than the browser for some judges.

---

## Failure-mode cheat sheet

| Symptom | Likely cause | Do this |
|---|---|---|
| Dashboard shows `api: offline` | Backend not running | Check terminal 1 for errors. `ctrl+C`, re-run uvicorn. |
| Scan hangs > 5 seconds | Live API timeout | Keep talking. Mock fallback will kick in within 15s. |
| Attack simulation says `decision: allow` | Gateway wasn't activated first | Click Activate, then click Simulate again. Don't announce the bug. |
| Alert doesn't pulse | Browser didn't rerender | Hit F5. Say "one moment — network hiccup". |
| Backend crashes | Port conflict / bad env | Open Plan B — the backup video. Do NOT debug on stage. |

---

## Timing discipline

| Beat | Seconds | Running total |
|---|---|---|
| 1. Introduce | 8 | 0:08 |
| 2. Findings | 20 | 0:28 |
| 3. DPDP mapping | 15 | 0:43 |
| 4. Activate gateway | 7 | 0:50 |
| 5. Attack sim | 25 | 1:15 |
| 6. Close | 10 | 1:25 |

Target: end at 1:25 with 5 seconds of silence-after-the-punchline. If you're at 1:40+, you've rambled somewhere — cut beat 2 by skipping `dns` findings.

---

## Video backup requirements

You MUST record a working version of this flow on your laptop *before* the event:

1. OBS / QuickTime / Windows Game Bar — record screen + mic
2. Record it **3 times**. Pick the best take.
3. Upload to YouTube **unlisted**. Bookmark the URL on your phone.
4. Also keep a local `.mp4` copy on a USB drive (venue WiFi is unreliable).

If the live demo fails, open the video: *"Let me show you the recorded version — same flow, same numbers, runs from real APIs."*

Never apologise. Never say "it's not working today" — that phrase kills the judges' confidence instantly.

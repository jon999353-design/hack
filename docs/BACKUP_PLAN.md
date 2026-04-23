# Backup Plan — When The Demo Gods Frown

Murphy's Law at hackathons is: **something will break, during your slot, on stage, with judges watching.** The difference between the winning team and everyone else is that the winning team practised the fallback.

This doc lists every plausible failure mode and what to do in under 10 seconds.

---

## Layer 1 — "Plan A" is always running

Your demo environment at the venue should always be:

- Backend running **locally** on `127.0.0.1:8765` — does not need the internet
- Frontend pointing at `127.0.0.1:8765` via `window.VG_API = 'http://127.0.0.1:8765'`
- `DEMO_MODE=true` in `.env` so mocks are blended in
- `paytrust-partner.com` scan **pre-warmed** (cached) so the first click is instant

If all four are true, **no external network can break your demo.**

---

## Layer 2 — Three fallbacks, in order

### Fallback #1 — Switch to terminal demo (if browser breaks)

Browser won't load? Dashboard shows blank? CSS broken?

→ Switch to the terminal running `python scripts/demo_attack.py`. The Rich TUI shows the same flow with colour panels. Say:

> **"I'll walk you through the backend directly — every pixel on the dashboard is a REST call; we'll skip the UI and show the API response."**

This actually *impresses* more technical judges. They see you wrote real code, not just a pretty mock.

### Fallback #2 — Play the backup video

Backend crashed? `python` exits with an error? Laptop freezes?

→ Open your pre-recorded YouTube video (unlisted) or the local `.mp4` on a USB drive. Say:

> **"I'll show you the recorded version of the exact same flow — this runs on the same backend, same data, in production."**

**Never call it a "backup" video.** Call it the "recorded version" or "the production clip". Subtext matters.

### Fallback #3 — Whiteboard the flow

Laptop is dead. Projector is broken. You're in front of 8 judges with nothing.

→ Walk to the whiteboard. Draw 6 boxes left to right. Label them:
`Domain → Scan → AI Risk → DPDP Map → Trust Score → Alert`

Narrate the attack scenario as a story. Say:

> **"Picture a vendor trying to export 12,000 records. At box 2, our scanner sees it. At box 4, DPDP Act Section 8(5) maps it to ₹250 crore. At box 6, we've blocked it and WhatsApp'd the CISO. Total time: 3.15 seconds."**

A well-told story on a whiteboard beats a broken demo every time.

---

## Common failure modes + exact recovery

| Symptom | Recovery (in order) |
|---|---|
| WiFi is down | You're already local. Demo continues. Say nothing. |
| Battery warning | Plug in. If no outlet, switch to a teammate's laptop (mirror repo on a USB drive beforehand). |
| `uvicorn` refuses to start (port in use) | `lsof -i :8765` → `kill <pid>` → restart. Do this in 5 seconds or pivot to video. |
| Frontend is blank | Check browser console. If CORS error — ensure backend is on port 8765 and frontend points there. Otherwise go to Fallback #1 terminal. |
| Scan returns 0 findings | `DEMO_MODE` got turned off. Set `DEMO_MODE=true` in `.env`, restart backend. |
| AI summary says "undefined" or errors | AI is optional. The template fallback always works. If UI shows error, it's a frontend bug — screenshot it later, demo continues. |
| Judge interrupts with hostile question mid-demo | "Great question — let me answer that right after this next beat" + keep going. Don't let them derail the 3.15 seconds moment. |
| WhatsApp alert didn't send | It's logged to the terminal. Point at terminal 1: "Here's the alert payload — Twilio sandbox rate-limited us but dispatch happened. You'd see this on your phone in production." |
| You forget the one-liner | Say: "the only vendor risk scanner that speaks DPDP." That's your safe word. |

---

## Pre-event hardware checklist (night before)

- [ ] Laptop charged to 100%
- [ ] Charger + adapter packed
- [ ] USB-C to HDMI dongle (venues love surprising you with the wrong port)
- [ ] USB drive with: backup video, repo zip, PDF deck
- [ ] Phone charged — hotspot plan ready
- [ ] Two bottles of water
- [ ] Printed copy of pitch scripts (if phone dies)
- [ ] Slack / WhatsApp group with team for on-stage coordination

---

## Dry-run rule

You should run the full demo **at least 5 times** before demo day. Not the first 5. The *last* 5 — same laptop, same WiFi setting, same posture, same room if possible.

If you can't run it 5 times without a single glitch, you are not ready. Keep rehearsing.

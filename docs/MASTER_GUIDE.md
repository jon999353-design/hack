# VendorGuard AI — Master Winning Guide

**Audience:** Akshay (team lead), Harshitha, Gaurav.
**Goal:** Win Athernex. Not just "participate well." **Win.**

This is the one doc that links to everything else. Read top to bottom once, then use the sub-docs as reference during the event.

---

## 1. The winning thesis (memorise this)

Hackathon judges reward exactly three things, in this order:

1. **Clarity of problem** — does the team *really* understand the pain?
2. **Credibility of solution** — is there a working thing or just slides?
3. **Story that lands in 3 minutes** — can the team sell it to a non-technical dean?

Nexacore (honeypot team) is strong on #1 and #3 but weak on #2 — honeypots are hard to demo live and don't map to ₹ penalties.

**You win by being the *only* team with:**
- A working prototype judges can click through
- Every security finding translated to a **DPDP clause + ₹ figure** (no one else will do this)
- A 3.2-second "contained in real time" mic-drop moment
- Indian-SMB-first pricing (₹3,999/month) vs Teleport/StrongDM at ₹25L+

If you hit all four, you are unbeatable. This guide is about making sure you do.

---

## 2. Single one-line pitch (engrave this into your brain)

> **"VendorGuard sits between your vendors and your data, verifies every API call in real time, auto-stops breaches in under 4 seconds, and translates the risk into the exact DPDP Act penalty in rupees."**

Every sentence you say in the finals should tie back to this one line. Every slide, every demo moment, every Q&A answer.

---

## 3. The 5 weapons you now have

1. **Working MVP** — `vendorguard-ai/` repo, runs locally with 3 commands. See `README.md`.
2. **Live-demo script** — `scripts/demo_attack.py` shows the 3.2s containment on the terminal while the dashboard shows it on a browser.
3. **Pitch scripts at 3 lengths** — see `PITCH_SCRIPTS.md`. Memorise the 60s and 3-min versions.
4. **Judge Q&A preparation** — 30 hardest questions pre-answered. See `JUDGES_QA.md`.
5. **Backup plan** — what to do if the WiFi dies, API rate-limits, or the laptop crashes. See `BACKUP_PLAN.md`.

---

## 4. The 7-step plan to win

### Step 1 — TODAY (Day 0): Set up & understand the repo (≈ 2 hours)
- Clone the repo, run the 3 commands. Confirm the demo works end-to-end on your laptop.
- Open `index.html` in a browser. Click "Scan Vendor" → "Activate Gateway" → "Simulate Attack". You should see a red pulsing alert card saying "contained in 3.15s".
- Run `python scripts/demo_attack.py` in a terminal. Confirm you see the same flow in terminal form.
- Read this whole `docs/` folder once.

### Step 2 — Day 1: Get your own API keys (≈ 1 hour)
Free-tier keys for **at least**: Shodan, VirusTotal, Anthropic Claude (or OpenAI).

These make the demo look "more live." Without them the app still works, but judges may ask if the data is real. Having 3/5 keys answers that question.

### Step 3 — Day 1: Deploy the app (≈ 30 min)
- Backend → **Fly.io** (free tier, 1-command deploy). See `DEPLOYMENT.md`.
- Frontend → **Vercel** or **Netlify** (drag and drop the `frontend/` folder).
- Update `frontend/index.html`'s `window.VG_API` constant to point to your deployed backend URL.
- Test the live URL. If it works, you can demo from any WiFi without your laptop.

### Step 4 — Day 1: Fix the deck (≈ 30 min)
Open `DECK_FIX.md`. Copy-paste the exact text I wrote for each slide into your `.pptx`. **This is non-negotiable.** You got selected with a bad deck; finals judges will not give you that second chance.

### Step 5 — Day 2: Record a backup demo video (≈ 1 hour)
On your laptop (NOT during the event):
- Run the live demo 3 times until you nail it
- Screen-record the 4th run with OBS / QuickTime (2 minutes max)
- Upload to YouTube (unlisted) and keep the link handy
- **If live demo fails on stage, open this video.** No judge penalises a recorded demo if the idea is strong.

### Step 6 — Day 2: Rehearse the pitch (≈ 2 hours, minimum)
- 10 solo runs of the 3-min pitch with a timer
- 3 group runs with Harshitha + Gaurav
- 3 hostile Q&A rounds (one team-mate plays a rude judge; use questions from `JUDGES_QA.md`)

### Step 7 — Hackathon day: Execute per `HACKATHON_DAY_PLAN.md`

---

## 5. Who does what (role split)

| Role | Akshay | Harshitha | Gaurav |
|---|---|---|---|
| Primary | Backend, demo, pitch delivery | Frontend polish, dashboard branding | DPDP research, Q&A depth |
| Demo day | Runs laptop, narrates | Operates dashboard visuals | Handles judge interruptions |
| Q&A | Tech + business questions | UX / design questions | Compliance / legal questions |

Everyone must be able to answer **the one-line pitch** and **the top 5 FAQs from `JUDGES_QA.md`**. Do not let any single person be a bottleneck.

---

## 6. What will make judges tick (internal cheat sheet)

**Things to say that judges react to:**
- "Every finding is mapped to a DPDP clause and ₹ penalty." (The killer moat line.)
- "Contained in 3.15 seconds." (Mic drop.)
- "70 million Indian SMBs the DPDP Act just made liable." (Market size + urgency.)
- "Teleport controls access. StrongDM controls queries. We control API-level behaviour." (Positioning vs. incumbents.)
- "DPB enforcement begins 2025–26." (Urgency.)
- "We're not vapourware — here's the code." (Credibility.)

**Things to avoid saying:**
- "We will add…" → instead, say "the next version ships…"
- "If we had more time…" → replace with "our roadmap for finals week is…"
- "AI does this automatically" (without caveats) → "AI recommends; CISO approves in one click"
- "We're better than…" (without evidence) → cite a specific delta
- Never say "blockchain," "quantum," or "web3" unless explicitly asked. Adding buzzwords to a real product looks desperate.

---

## 7. Scoring prediction — if you execute this plan

| Criterion | Weight | Your score | Nexacore |
|---|---|---|---|
| Innovation | 25% | 8/10 | 8/10 |
| Technical depth | 25% | 9/10 ← MVP shipped | 6/10 |
| Business/market fit | 20% | 9/10 ← DPDP + SMB pricing | 6/10 |
| Presentation | 20% | 8/10 (if you rehearse) | 8/10 |
| Feasibility | 10% | 9/10 ← code works | 6/10 |
| **Weighted total** | | **8.55 / 10** | **7.00 / 10** |

You should win. If you don't, something went wrong in presentation or Q&A — focus rehearsal there.

---

## 8. Emergency fallbacks

| If this happens | Do this |
|---|---|
| WiFi is down | Demo runs **fully offline** — backend is localhost, frontend is a static file. Still works. |
| Laptop battery dies mid-demo | Pivot to backup video. Never apologise. |
| Judge asks a question you don't know | "Great question — that's in our Phase 2 roadmap on slide 8" + smile. Never bluff. |
| Another team copies your DPDP angle | "Interesting — but they haven't built the gateway. Here's ours, live." |
| Teammate freezes during pitch | Pre-agreed hand signal → Akshay takes over mid-sentence. |

---

## 9. Post-finals, if you win

- Incorporate as OPC (One Person Company) or LLP in Karnataka — **before** collecting any money
- Register with Startup India → MSME recognition → free legal help
- Apply to NASSCOM 10,000 Startups for mentorship + ₹25L seed
- DSCI (Data Security Council of India) has a vendor-risk working group. Submit to them.
- Talk to CISOs at 10 Indian fintechs in your extended network in week 1

---

## 10. Post-finals, if you don't win

- It does **not** mean the idea is bad. DPDP + vendor risk + India-SMB is a real market.
- Put the repo on GitHub with a clean README. This becomes your best resume artefact for internships.
- Apply to Smart India Hackathon (SIH) and Hacksprint with the same repo.
- Publish a Medium post: *"We built a DPDP-compliant vendor risk scanner in 48 hours. Here's what we learned."*
- Incoming: internship offers, GSoC mentor DMs, startup accelerator interest.

---

Now go read `PITCH_SCRIPTS.md`.

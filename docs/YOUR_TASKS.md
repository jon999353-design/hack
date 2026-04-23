# What I Built vs. What You Must Build During the Hackathon

A clear split so nothing slips through the cracks.

---

## ✅ What I built for you (shipped, tested, working)

### Backend (Python / FastAPI)
| File | What it does |
|---|---|
| `backend/app/main.py` | FastAPI app with 9 endpoints: `/scan`, `/gateway/activate`, `/gateway/proxy`, `/gateway/status/{vendor}`, `/alerts`, `/vendors`, `/health`, `/scan/{vendor}`, `/` |
| `backend/app/modules/osint.py` | Parallel Shodan + HIBP + crt.sh + VirusTotal + DNS + TLS scanner, with deterministic mock fallback |
| `backend/app/modules/trust_score.py` | 7-input weighted Trust Score formula, Safe/Watch/Block bands |
| `backend/app/modules/dpdp.py` | Finding→clause mapper, ₹ exposure calculator |
| `backend/app/modules/ai_risk.py` | Claude / OpenAI summary with deterministic template fallback |
| `backend/app/modules/gateway.py` | Behavioural rule engine: scope violation, rate limit, token revoke, endpoint lock |
| `backend/app/modules/alerts.py` | Twilio WhatsApp + console fallback |
| `backend/app/modules/store.py` | In-memory scan cache |
| `backend/app/data/dpdp_clauses.json` | Digital Personal Data Protection Act, 2023 — 7 clauses with section, obligation, max penalty, immediate action, liability note |
| `backend/app/data/demo_vendors.json` | Seeded demo vendor `paytrust-partner.com` with 6 realistic findings |

### Frontend (HTML + Tailwind CDN)
- `frontend/index.html` — single-page dashboard with Trust Score ring, findings list, DPDP table, gateway controls, live-alert feed with pulse animation

### Scripts
- `scripts/demo_attack.py` — full end-to-end demo driver using Rich TUI. Hit Enter and it runs the scan → activate gateway → simulate attack → print "contained in 3.15s"

### Documentation (9 files in `docs/`)
- `MASTER_GUIDE.md` — the single winning playbook
- `PITCH_SCRIPTS.md` — 60-second, 90-second, 3-minute versions, memorisation-ready
- `JUDGES_QA.md` — 30 hardest questions with ≤25s answers
- `DEMO_RUNBOOK.md` — beat-by-beat live demo script
- `BACKUP_PLAN.md` — every failure mode + recovery
- `DECK_FIX.md` — exact text for all 9 slides
- `HACKATHON_DAY_PLAN.md` — hour-by-hour schedule
- `OPEN_SOURCE_ARSENAL.md` — curated tools (ProjectDiscovery, LangChain, NGINX, Wazuh, OpenCanary, OpenSearch Anomaly, Amass, Semgrep, Prowler)
- `DEPLOYMENT.md` — Fly.io + Vercel in 15 minutes
- `YOUR_TASKS.md` — this file
- `README.md` — top-level overview

### Verified working
- ✅ Backend starts on port 8765, `/health` returns 200
- ✅ `POST /scan` returns 6 findings, Trust Score 44/100, ₹450 Cr exposure
- ✅ `POST /gateway/activate` + `POST /gateway/proxy` with 12,000 records → `decision: "block"` + auto-response event fires
- ✅ `scripts/demo_attack.py` renders the full story with Rich panels in ~5 seconds
- ✅ Frontend `index.html` hits the local backend, renders score ring, DPDP table, and alert-pulse animation

---

## 🛠️ What YOU must build during the hackathon

### ZERO-CODE tasks (≈ 3 hours total)

#### 1. Get API keys (60 min)
- [ ] Sign up for Shodan — https://account.shodan.io/register → copy key to `SHODAN_API_KEY`
- [ ] Sign up for VirusTotal — https://www.virustotal.com/gui/join-us → copy key to `VIRUSTOTAL_API_KEY`
- [ ] Sign up for Anthropic — https://console.anthropic.com/ → $5 free credits → `ANTHROPIC_API_KEY`
- [ ] (Optional but impressive) HIBP — https://haveibeenpwned.com/API/Key → $3.95 one-time → `HIBP_API_KEY`
- [ ] (Optional for WhatsApp wow) Twilio sandbox — https://www.twilio.com/try-twilio → sandbox free

#### 2. Deploy (30 min)
Follow `docs/DEPLOYMENT.md` step by step:
- [ ] Deploy backend to Fly.io (Mumbai region)
- [ ] Deploy frontend to Vercel
- [ ] Update `window.VG_API` in `index.html` to your Fly.io URL
- [ ] Test the deployed version from your phone on 4G

#### 3. Fix the PPT (30 min)
Open `docs/DECK_FIX.md`, copy-paste the exact text into each of the 9 slides. This is the single biggest visible lift.

#### 4. Record a backup demo video (60 min)
Follow `docs/DEMO_RUNBOOK.md` to do 3 clean runs. Record the best one with OBS or QuickTime, upload to YouTube unlisted.

---

### REHEARSAL tasks (≈ 4 hours total)

#### 5. Memorise the pitch (2 hours)
- [ ] 60-second pitch — 20 solo runs until you can recite it with a stopwatch
- [ ] 3-minute pitch — 10 solo runs, 3 team runs
- [ ] Have Gaurav play a hostile judge and ask 10 random questions from `JUDGES_QA.md`

#### 6. Demo rehearsal (2 hours)
- [ ] 5 clean runs of the browser-dashboard demo
- [ ] 3 clean runs of the terminal fallback
- [ ] 1 run simulating "WiFi is dead" — you should be able to continue without internet

---

### NICE-TO-HAVE code tasks (if you finish above with time to spare)

#### 7. ProjectDiscovery integration (1 hour) 🥇
Replace DIY DNS with `subfinder`/`httpx`/`nuclei`. See `docs/OPEN_SOURCE_ARSENAL.md` code snippet. Immediate credibility boost.

#### 8. RAG over DPDP Act PDF with LangChain (1 hour) 🥇
Download the gazette PDF, index with ChromaDB, have Claude cite actual paragraphs. See `OPEN_SOURCE_ARSENAL.md`.

#### 9. Branding polish on the frontend (30 min) 🥈
- [ ] Replace `V` initials logo with your team logo (or a ₹ symbol → easy sell to Indian judges)
- [ ] Swap the amber accent (`amber-400`) for your team colour if you have one
- [ ] Change the footer: `Built for the Athernex Hackathon (DSCE × BMSCE) · Team Rashi Innovators` — add your actual team name

#### 10. Add a second demo vendor (30 min) 🥈
Edit `backend/app/data/demo_vendors.json` — add a second vendor (e.g., `logistics-partner.com`) with different findings. Judges like seeing you handle >1 case.

#### 11. Add CI/CD badge on GitHub (15 min) 🥉
Run a simple GitHub Actions workflow that installs requirements and imports the modules. Green badge on the README = looks professional.

#### 12. Add Prometheus-style metrics (1 hour) 🥉
Install `prometheus-fastapi-instrumentator`. Three lines in `main.py`. Adds a `/metrics` endpoint. Tell judges: "Production-ready observability from day 1."

---

### STRETCH tasks (only if you have a full clear evening)

#### 13. Real NGINX gateway with openresty Lua (3-4 hours) 🥈
Replace the FastAPI gateway with a real NGINX config. Harder, but makes the architecture slide look serious. See `OPEN_SOURCE_ARSENAL.md`.

#### 14. Contract Intelligence Layer MVP (4 hours) 🥉
Upload a contract PDF → Claude highlights missing DPDP clauses → auto-inserts suggested language. This is the Layer 5 from your pitch. Adds "we built all 5 layers."

#### 15. Insurance integration stub (2 hours) 🥉
Add a mocked `/insurance/quote` endpoint that returns a premium discount based on Trust Score. Tells the story of "we don't just sell scans, we unlock business value."

---

## The 2-day minimum path to showing up credible

If you only have 2 days of actual work, do **exactly this** in order:

**Day 1 (4 hours)**
1. (30 min) Run the stack locally — confirm everything works
2. (60 min) Get Shodan + Anthropic + VirusTotal API keys
3. (60 min) Update `.env`, test with real APIs
4. (30 min) Fix deck per `DECK_FIX.md`
5. (60 min) Record backup demo video

**Day 2 (4 hours)**
1. (60 min) Deploy to Fly.io + Vercel
2. (2 hrs) Rehearse pitch (solo + team)
3. (60 min) Hostile Q&A with a friend

That's 8 hours of work spread over 2 days. If you do this minimum, you show up with:
- A working live demo (deployed)
- A polished deck
- A video fallback
- 30 memorised Q&A answers
- Clean 3-minute pitch

That's already top-5 material. Anything beyond this is upside.

---

## The mental model

- **I built the "product"**: code, docs, data, design
- **You build the "performance"**: deployment, deck fix, rehearsal, Q&A prep

Nobody wins a hackathon because the product is perfect. They win because **the 3-minute story lands with judges who don't have time to read code.** So over-invest in rehearsal, not in more features.

If you nail the pitch, you win.
If you add 5 more features but stumble through the demo, you lose.

Focus.

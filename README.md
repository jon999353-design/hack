# VendorGuard AI  &nbsp;·&nbsp; v2.0

> **The Vendor Access Control Plane for DPDP-compliant India.**
> Scan → Score → Gateway-protect → Auto-respond — with every finding mapped to a DPDP Act clause and ₹ penalty.

![status](https://img.shields.io/badge/status-hackathon%20ready-success) ![stack](https://img.shields.io/badge/stack-FastAPI%20%2B%20Tailwind-blue) ![ml](https://img.shields.io/badge/ML-IsolationForest-6366f1) ![nuclei](https://img.shields.io/badge/scanner-ProjectDiscovery%20nuclei-ef4444) ![rag](https://img.shields.io/badge/DPDP-RAG%20over%20Gazette-f59e0b) ![pdf](https://img.shields.io/badge/report-ReportLab%20PDF-0f766e) ![sse](https://img.shields.io/badge/live-SSE%20alerts-0ea5e9) ![license](https://img.shields.io/badge/license-MIT-green)

Built for **Athernex** (DSCE × BMSCE) by Team Rashi Innovators.

---

## What's new in v2.0

- **Real containment time** — the old `+3.15s` demo offset is gone. The number on stage is the measured wall-clock time from request entry to gateway decision.
- **Behavioural AI** — gateway requests are scored by an unsupervised **scikit-learn IsolationForest** trained on seeded baseline traffic. Every alert now carries an `anomaly_score`.
- **ProjectDiscovery `nuclei`** — wired in as a subprocess with 8,000+ CVE templates. Absent binary → graceful mock fallback (ships with realistic nuclei CVE findings so the demo is rock-solid offline).
- **SQLite persistence** via `aiosqlite` — scans, gateway state, alerts, canary tokens all survive restarts.
- **Board-ready PDF report** — `GET /report/{vendor}.pdf` renders a ReportLab CISO deck with trust score, findings, and DPDP obligations quoted from the Act.
- **DPDP Act RAG** — TF-IDF retriever over 14 verbatim gazette passages. Every DPDP mapping carries `rag_quote` + `rag_citation`. Drop the real Act PDF into `.env` and it re-indexes on boot.
- **Live dashboard** — `GET /alerts/stream` is an SSE endpoint; the frontend `EventSource` subscribes and renders alerts in real time.
- **Vendor-relationship graph** — `GET /graph` + Cytoscape.js view of your company in the centre, vendors on the rim, edges coloured by band.
- **Canary tokens** — mint tripwire endpoints for a vendor, trip them, see a critical alert fire. Absorbs the honeypot angle any competitor might pitch.
- **Expanded DPDP catalog** — 7 → **15 clauses** (§4, §5, §6, §7, §8(4–8), §9, §10, §11, §16, §17, §33).
- **4 demo vendors** — `paytrust-partner.com` (payments), `shopquick-vendor.com` (e-commerce), `healthbuddy-partner.com` (healthtech), `databridge-cloud.com` (cloud/cross-border).
- **Tests + Docker + Deploy** — 14-case pytest smoke suite, Dockerfile, `docker-compose.yml`, `fly.toml`, `railway.json`, `frontend/vercel.json`, `scripts/preload_demo.py`. See `DEPLOY_QUICKSTART.md`.

See `WHAT_WE_UPGRADED.md` for the full before/after breakdown.

---

## What this is

A working MVP that demonstrates all 4 runtime layers pitched in the deck:

1. **Pre-Onboarding Intelligence** — OSINT scan: Shodan, HaveIBeenPwned, crt.sh, VirusTotal, DNS, TLS, **ProjectDiscovery nuclei** (with graceful mock fallback).
2. **Trust Score Engine** — capped weighted score, 0–100, Safe / Watch / Block bands.
3. **DPDP Compliance Mapper** — each finding → DPDP Act 2023 clause → ₹ penalty → verbatim Act quote (RAG).
4. **Vendor Access Gateway** — IsolationForest ML + rule-based policy + autonomous response + WhatsApp/SSE alerts.

Layer 5 (Contract Intelligence) is documented as a **finals-stretch feature** in `docs/HACKATHON_DAY_PLAN.md`.

---

## Quick start (3 commands)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8765 --reload
```

Open the frontend in another terminal:

```bash
cd frontend
python3 -m http.server 5173
# then open http://localhost:5173
```

Optional — run the live attack demo from a third terminal:

```bash
python scripts/demo_attack.py
```

Optional — pre-warm all 4 demo vendors (recommended right before going on stage):

```bash
python scripts/preload_demo.py                  # against local backend
python scripts/preload_demo.py https://<backend> # against a deployed backend
```

That's it. With zero API keys, everything still runs because `DEMO_MODE=true` seeds realistic data for the 4 bundled demo vendors.

### Pointing the frontend at a remote backend

The frontend has **no hardcoded backend URL**. It resolves the API URL at runtime from (in order): `?api=` query string → `localStorage['VG_API']` → `<meta name="vg-api">` → `window.__VG_API_FALLBACK__` in `config.js` → `http://127.0.0.1:8765`. To point a Vercel deploy at a Railway/Fly backend without redeploying, just visit once with:

```
https://<your-frontend>/?api=https://<your-backend>
```

It's cached in `localStorage` on first visit.

---

## Add real API keys (optional, only for WOW factor)

Copy `backend/.env.example` to `backend/.env` and fill in whichever you have. Every key is optional — missing keys silently fall back to mock data.

| Integration | Free-tier signup | Env var |
|---|---|---|
| Shodan | https://account.shodan.io/register | `SHODAN_API_KEY` |
| HaveIBeenPwned | https://haveibeenpwned.com/API/Key ($3.95 one-time) | `HIBP_API_KEY` |
| VirusTotal | https://www.virustotal.com/gui/join-us | `VIRUSTOTAL_API_KEY` |
| Anthropic Claude | https://console.anthropic.com/ ($5 free credit) | `ANTHROPIC_API_KEY` |
| OpenAI (or any OpenAI-compatible gateway — Groq, Together, Ollama, vLLM) | https://platform.openai.com/ | `OPENAI_API_KEY` (+ `OPENAI_BASE_URL` for gateways) |
| OpenRouter (200+ models via one key, incl. Claude) | https://openrouter.ai/keys | `OPENROUTER_API_KEY` + `AI_PROVIDER=openrouter` |
| Twilio WhatsApp | https://www.twilio.com/try-twilio (sandbox is free) | `TWILIO_*` |

---

## Architecture

```
  ┌─ Frontend (HTML + Tailwind)  ──────────────────────────────┐
  │   Trust Score ring · Findings · DPDP table · Gateway · Alerts│
  └────────────────────────────┬─────────────────────────────────┘
                               │ REST + JSON
  ┌────────────────────────────▼─────────────────────────────────┐
  │                    FastAPI backend                            │
  │  /scan  /trust-score  /dpdp-map  /gateway/*  /alerts          │
  └─┬────┬────────────┬────────────┬────────────┬────────────────┘
    │    │            │            │            │
    ▼    ▼            ▼            ▼            ▼
  osint  trust_score  dpdp         gateway      alerts
  .py    .py          .py          .py          .py
    │
    ├─ httpx → Shodan / HIBP / crt.sh / VirusTotal
    ├─ dnspython → SPF / DMARC
    └─ socket+ssl → TLS probe
```

---

## Repo layout

```
vendorguard-ai/
├── backend/
│   ├── app/
│   │   ├── main.py          ← FastAPI app
│   │   ├── schemas.py       ← Pydantic models
│   │   ├── config.py        ← env settings
│   │   ├── data/
│   │   │   ├── dpdp_clauses.json
│   │   │   └── demo_vendors.json
│   │   └── modules/
│   │       ├── osint.py      ← Shodan/HIBP/crt.sh/VT/DNS/TLS
│   │       ├── trust_score.py
│   │       ├── dpdp.py
│   │       ├── ai_risk.py    ← Claude / OpenAI / template fallback
│   │       ├── gateway.py    ← behavioural rules + auto-response
│   │       ├── alerts.py     ← Twilio WhatsApp
│   │       └── store.py
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   └── index.html           ← single-page dashboard
├── scripts/
│   └── demo_attack.py       ← live 3.2s-containment demo
├── docs/
│   ├── MASTER_GUIDE.md        ← start here
│   ├── PITCH_SCRIPTS.md       ← 60s / 90s / 3-min
│   ├── JUDGES_QA.md           ← 30 hard questions
│   ├── DEMO_RUNBOOK.md        ← step-by-step live demo
│   ├── BACKUP_PLAN.md         ← if demo breaks
│   ├── DECK_FIX.md            ← exact slide-by-slide text
│   ├── HACKATHON_DAY_PLAN.md  ← hour-by-hour plan
│   ├── OPEN_SOURCE_ARSENAL.md ← tools to plug in
│   └── DEPLOYMENT.md          ← deploy to Fly/Railway/Vercel
└── README.md
```

---

## License

MIT — use freely. Built 2025.

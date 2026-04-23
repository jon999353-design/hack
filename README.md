# VendorGuard AI  &nbsp;·&nbsp; v3.2.1

> **The Vendor Access Control Plane for DPDP-compliant India.**
> Scan → Score → DPDP-map → Gateway-protect → **Fix the contract** → **Ship the audit ZIP** → **Play the backup video** — every finding grounded in the DPDP Act (§-numbered, gazette-page cited, ₹-penalty mapped) and crosswalked to ISO 27001 / SOC 2 / NIST CSF.

![status](https://img.shields.io/badge/status-hackathon%20ready-success) ![stack](https://img.shields.io/badge/stack-FastAPI%20%2B%20Tailwind-blue) ![ml](https://img.shields.io/badge/ML-IsolationForest-6366f1) ![rules](https://img.shields.io/badge/rules-16%20DPDP%20contract%20rules-f59e0b) ![rag](https://img.shields.io/badge/RAG-49%20passages-f59e0b) ![osint](https://img.shields.io/badge/OSINT-crt.sh%20live-10b981) ![selftest](https://img.shields.io/badge/selftest-4%2F4%20benchmark%20DPAs-10b981) ![tests](https://img.shields.io/badge/pytest-31%2F32-10b981) ![license](https://img.shields.io/badge/license-MIT-green)

Built for **Athernex 2026** (DSCE × BMSCE) by Team Rashi Innovators.

> For the pitch script + judge Q&A cheat sheet → see [`PITCH.md`](./PITCH.md).
> For the competitive landscape (OneTrust / Securiti / BigID / Tsaaro) → see [`COMPETITIVE.md`](./COMPETITIVE.md).

## Why we win (30-second read)

1. **DPDP-native, not GDPR-retrofitted.** Every rule is §-numbered, gazette-page cited, ₹-penalty mapped, and crosswalked to ISO 27001 / SOC 2 / NIST CSF. OneTrust's DPDP module is a rebrand; ours is built *from* the Act.
2. **Evidence trace on every verdict.** Red / amber / green + confidence (0.55-0.99) + keyword + offset + snippet + Act quote at the right gazette page + ready-to-counter-sign rewrite. Auditable by a non-lawyer in 15 seconds.
3. **Reproducible rule-engine self-test.** `GET /selftest` runs all 4 benchmark DPAs through Contract Intelligence and verifies every verdict matches the expected one baked into `backend/app/data/benchmark_dpas.json`. Not a black box — a provable one.
4. **One-click DPDP Audit ZIP.** `GET /audit/{vendor}.zip` bundles scan.json + playbook.json + alerts.json + CISO board PDF + CERT-In 6-hour Form-A PDF + README. Hand this to the Data Protection Board.
5. **Real-time containment, not just reporting.** IsolationForest + deterministic rules decide, autonomous response (token revoke, endpoint lock) executes, WhatsApp / Slack / SSE fires — **sub-100-ms measured end-to-end**.

---

## 5-layer architecture

```
L1  OSINT            Shodan · HIBP · crt.sh (live) · VT · DNS · TLS · nuclei
           │
           ▼
L2  Trust score      0-100 weighted composite · band (safe / watch / block)
           │
           ▼
L3  DPDP mapping     15 clauses · ₹ penalty · RAG citation (49-passage corpus)
                     + ISO 27001 / SOC 2 / NIST CSF crosswalk
           │
           ▼
L4  Runtime gateway  IsolationForest + deterministic rules · <100ms containment
                     · canary tripwires · webhook dispatch
           │
           ▼
L5  Contract Intel   16 rules · evidence trace (keyword+offset+snippet+conf)
                     · red/amber/green verdict · Act quote · rewrite
```

## What's new in v3.2.1 (polish round)

- **RAG clause-reference boost** — `backend/app/modules/rag.py` now detects `§X(y)`, `Section X`, `Sec X`, `Rule N`, `Schedule N` references in a query and strongly boosts passages whose `section` tag matches. Previously "penalties under §8(5)" returned §32 via word-overlap on "penalty"; now it returns §8(5). Semantic fallback still works when no clause is named. New pytest case (`test_rag_ask_boosts_explicit_section_reference`) locks it in.
- **Copy drift fix** — Ask DPDP subtitle, Board Report footer, and this README all said "14 verbatim gazette passages" after the corpus grew to 49 in v3.1. Fixed in all three places.
- **Version chip alignment** — header chip, `__version__`, `/health`, and README title all now read `v3.2.1`.
- **Rule-engine `/selftest`** — unchanged from v3.2.1 rule-engine round: 4/4 benchmark DPAs pass, surfaced in the header as a clickable `selftest: 4/4 ✓` chip.
- **Stage-day demo assets** — `docs/DEMO_SCRIPT.md` (90-second cue-tagged narrator script) + `scripts/generate_voiceover.py` (Sarvam.ai Bulbul v3 TTS client, speaker `ratan`, Indian-English) + `scripts/record_demo.py` (Playwright headless walkthrough recorder driving `window.navTo()`) + `out/demo-voiceover.mp3` (2m40s) + `out/demo-final.mp4` (2m40s muxed video, the projector backup).
- **31 / 32 tests** passing. One pre-existing flake on `test_gateway_allows_normal_traffic` from the v3.1-winner branch (ML anomaly baseline persists across `/gateway/reset` for `paytrust-partner.com`). Passes in isolation; tracked for a follow-up.

## What was in v3.2

- **One-click DPDP Audit Evidence Bundle** — `GET /audit/{vendor}.zip` returns a ZIP containing `scan.json` + `playbook.json` + `alerts.json` + board-report PDF + CERT-In incident PDF (if any alert) + README. Ship directly to the Data Protection Board. Wired into the **Board PDF · Audit ZIP** sub-tab in Remediation.
- **Compliance Diff sub-tab** — picks any two historical scans of the same vendor and renders score delta, ₹ exposure delta, new/resolved findings, new/resolved DPDP clauses, summary. Backed by the existing `/scan/{v}/history` + `/scan/{v}/diff` endpoints.
- **Playbook CSV export** — `GET /playbook/{vendor}.csv` with Jira / Linear / GitHub-Projects-compatible headers (Vendor, Bucket, Section, Owner, SLA_days, Savings_INR, Title, Summary, Frameworks). One-click download button on the Playbook panel header.
- **Fourth benchmark DPA** — `saas-commodity-dpa` (commodity-SaaS GDPR-era boilerplate, DPDP-silent). Shows the rule engine behaviour on real-world global-SaaS language that isn't clearly weak but is clearly DPDP-uncompliant.
- **Demo mode v2** — 8-step pitch walk now clicks the Benchmark "Weak DPA" chip (so judges watch the rule engine fire on a reproducible canned DPA) and then flips to the new Compliance Diff sub-tab to show "since last scan" currency.
- **Rule engine self-test endpoint** (`GET /selftest`) — runs all 4 benchmark DPAs through Contract Intelligence and verifies every verdict matches the expected one. Reproducible audit with a single curl. Surfaced in the header as a live `selftest: 4/4 ✓` chip (click to re-run).
- **31 tests** passing at end of v3.2 (27 → 31: +audit bundle, +404 case, +playbook CSV, +saas-commodity benchmark, +selftest harness).

## What was in v3.1

- **Nav consolidation** — 13-item sidebar → **5 top-level panels** (Executive Board / Vendor Scan / Contract Intel / Live Defense / Remediation). Ask DPDP stays as the floating drawer (`/` hotkey). Sub-tabs handle depth. Built for a 90-second pitch arc.
- **Contract Intel v2** — 12 rules → **16 rules**. New: §9 children (verifiable parental consent, no profiling), §17 exemption over-claim, §8(3) accuracy, §8(5) log retention (Rule 6), §10 SDF uplift. Every verdict now carries a **confidence score** (0.55-0.99), **evidence trace** (keyword+offset+snippet), and **red_flags_trace**.
- **Benchmark Evidence Ledger** — 3 hand-written canned DPAs (strong / ambiguous / weak) with baked-in expected verdicts — expanded to 4 in v3.2 by adding `saas-commodity-dpa` (GDPR-era boilerplate, DPDP-silent). One-click auto-load + auto-analyse. Reproducible audit harness (`GET /benchmark/dpas`, `GET /benchmark/dpas/{id}`). None of the commercial incumbents expose an equivalent.
- **Live OSINT via crt.sh** — real Certificate Transparency subdomain enumeration (`GET /osint/live/{vendor}`) with a `verify_url` judges can open in crt.sh themselves. No API key required. Integrations banner now honestly reports `crt_sh / dns / tls` as live.
- **RAG corpus 14 → 49 passages** — full DPDP Act 2023 §§2-34 + **DPDP Rules 2025 R.1-R.22** + Schedules + CERT-In directions. §8(5) now retrieves §8(5), not §5.
- **Compliance Diff** — `GET /scan/{v}/diff?from=<scan_id>&to=<scan_id>`. Set-arithmetic delta between two historical scans: new findings, resolved findings, clause delta, score delta, ₹ exposure delta. Plus `GET /scan/{v}/history`.
- **Honest copy** — "AI-drafted" → "LLM polish (Claude / GPT, optional) · grounded in DPDP RAG" where the LLM actually runs. Header tagline is now **"Rules · ML · RAG · DPDP Rules 2025"** — no AI-washing.
- **27/27 tests** passing at end of v3.1 (was 23/23 in v3.0; grew to 32 cases by v3.2.1 polish).

## What was in v3.0

- **Layer 5 — Contract Intelligence** (`POST /contract/analyze`). Paste a vendor DPA; get per-clause red/amber/green, ₹ penalty, recommended rewrite, and DPDP Act gazette quote. 12 rules at v3.0 (grown to 16 in v3.1) cover §4, §5, §6, §7, §8(4–8), §9, §10, §11, §16, §17. Optional `polish_rewrites=true` calls Claude/GPT/OpenRouter to soften the template language.
- **Executive Board** (`GET /portfolio`). Cross-vendor KPIs: vendors tracked, avg trust score, total ₹ exposure, attacks blocked, ₹ saved; band histogram; worst-offender leaderboard; top DPDP clauses triggered; ISO 27001 / SOC 2 / NIST CSF crosswalk chips — all in one screen.
- **Monday Playbook** (`GET /playbook/{vendor}`). Remediation checklist grouped by DPDP clause, sorted by ₹ impact, with owner, SLA (7 / 30 / long), triggering findings, RAG quote and framework crosswalk per row.
- **Framework crosswalk** (`GET /framework/crosswalk`). Every DPDP finding now carries an `iso27001 / soc2 / nist_csf` control list — written in machine-readable form for GRC pipelines.
- **CERT-In 6-hour report** (`GET /incident/{alert_id}.pdf`). Pre-filled Form-A equivalent PDF for an in-progress breach. Hand to the regulator in under 6 hours.
- **Bulk onboarding** (`POST /vendors/bulk`). Scan up to 25 domains in parallel.
- **Generic webhook alerts**. Set `ALERT_WEBHOOK_URL=…` and every gateway containment is dispatched as Slack-compatible JSON (works with Slack, Teams, PagerDuty, Zapier).
- **Live KPI ticker** (`GET /kpis`). Lightweight header chips: `₹ saved` + `blocks` — refresh every 15s.
- **Floating Ask DPDP drawer**. Press `/` from anywhere; get RAG answers with verbatim gazette citations.
- **Upgraded Demo Mode** — 7-step narrated walkthrough covering Executive Board → scan → DPDP → Playbook → Contract Intel → Gateway → Ask DPDP.

---

## What's new in v2.0

- **Real containment time** — the old `+3.15s` demo offset is gone. The number on stage is the measured wall-clock time from request entry to gateway decision.
- **Behavioural AI** — gateway requests are scored by an unsupervised **scikit-learn IsolationForest** trained on seeded baseline traffic. Every alert now carries an `anomaly_score`.
- **ProjectDiscovery `nuclei`** — wired in as a subprocess with 8,000+ CVE templates. Absent binary → graceful mock fallback (ships with realistic nuclei CVE findings so the demo is rock-solid offline).
- **SQLite persistence** via `aiosqlite` — scans, gateway state, alerts, canary tokens all survive restarts.
- **Board-ready PDF report** — `GET /report/{vendor}.pdf` renders a ReportLab CISO deck with trust score, findings, and DPDP obligations quoted from the Act.
- **DPDP Act RAG** — TF-IDF retriever over 49 verbatim passages (Act §§2-34 + DPDP Rules 2025 R.1-R.22 + CERT-In 6h directions). Every DPDP mapping carries `rag_quote` + `rag_citation`. Drop the real Act PDF into `.env` and it re-indexes on boot.
- **Live dashboard** — `GET /alerts/stream` is an SSE endpoint; the frontend `EventSource` subscribes and renders alerts in real time.
- **Vendor-relationship graph** — `GET /graph` + Cytoscape.js view of your company in the centre, vendors on the rim, edges coloured by band.
- **Canary tokens** — mint tripwire endpoints for a vendor, trip them, see a critical alert fire. Absorbs the honeypot angle any competitor might pitch.
- **Expanded DPDP catalog** — 7 → **15 clauses** (§4, §5, §6, §7, §8(4–8), §9, §10, §11, §16, §17, §33).
- **4 demo vendors** — `paytrust-partner.com` (payments), `shopquick-vendor.com` (e-commerce), `healthbuddy-partner.com` (healthtech), `databridge-cloud.com` (cloud/cross-border).
- **Tests + Docker + Deploy** — 14-case pytest smoke suite, Dockerfile, `docker-compose.yml`, `fly.toml`, `railway.json`, `frontend/vercel.json`, `scripts/preload_demo.py`. See `DEPLOY_QUICKSTART.md`.

See `WHAT_WE_UPGRADED.md` for the full before/after breakdown.

---

## What this is

A working MVP that demonstrates all 5 runtime layers pitched in the deck:

1. **Pre-Onboarding Intelligence** — OSINT scan: Shodan, HaveIBeenPwned, crt.sh, VirusTotal, DNS, TLS, **ProjectDiscovery nuclei** (with graceful mock fallback).
2. **Trust Score Engine** — capped weighted score, 0–100, Safe / Watch / Block bands.
3. **DPDP Compliance Mapper** — each finding → DPDP Act 2023 clause → ₹ penalty → verbatim Act quote (RAG) → ISO 27001 / SOC 2 / NIST CSF crosswalk.
4. **Vendor Access Gateway** — IsolationForest ML + rule-based policy + autonomous response + WhatsApp/SSE/webhook alerts + CERT-In 6-hour PDF.
5. **Contract Intelligence** — paste a vendor DPA; get per-clause red/amber/green, ₹ penalty, recommended rewrite, gazette quote and framework crosswalk.

---

## Quick start (3 commands)

```bash
python -m venv .venv && source .venv/bin/activate
cd backend
pip install -e .          # uses pyproject.toml; `pip install -r requirements.txt` also works
DEMO_MODE=true uvicorn app.main:app --host 127.0.0.1 --port 8765 --reload
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
│   │   ├── __init__.py      ← __version__ = "3.2.1"
│   │   ├── main.py          ← FastAPI app (30+ endpoints)
│   │   ├── schemas.py       ← Pydantic models
│   │   ├── config.py        ← env settings
│   │   ├── data/
│   │   │   ├── dpdp_clauses.json        ← 15 clauses + finding→clause map
│   │   │   ├── dpdp_act_excerpts.json   ← 49 verbatim RAG passages
│   │   │   ├── benchmark_dpas.json      ← 4 canned DPAs (strong/ambiguous/weak/saas)
│   │   │   ├── framework_crosswalk.json ← ISO27001/SOC2/NIST CSF
│   │   │   ├── baseline_traffic.json    ← seed for IsolationForest
│   │   │   └── demo_vendors.json
│   │   └── modules/
│   │       ├── osint.py            ← Shodan/HIBP/crt.sh/VT/DNS/TLS/nuclei
│   │       ├── nuclei.py           ← ProjectDiscovery subprocess wrapper
│   │       ├── trust_score.py      ← 0-100 weighted composite
│   │       ├── dpdp.py             ← finding → clause → ₹ penalty mapper
│   │       ├── rag.py              ← TF-IDF retriever + clause-ref boost (v3.2.1)
│   │       ├── anomaly.py          ← IsolationForest training + scoring
│   │       ├── gateway.py          ← behavioural rules + auto-response
│   │       ├── contract.py         ← 16 DPA rules + evidence trace (L5)
│   │       ├── compliance_diff.py  ← set-arithmetic scan diff
│   │       ├── portfolio.py        ← Executive Board KPIs
│   │       ├── playbook.py         ← Monday remediation checklist + CSV
│   │       ├── framework.py        ← ISO27001 / SOC2 / NIST CSF crosswalk
│   │       ├── canary.py           ← tripwire tokens
│   │       ├── report.py           ← board PDF (ReportLab)
│   │       ├── incident.py         ← CERT-In 6h Form-A PDF
│   │       ├── events.py           ← SSE stream + audit ZIP builder
│   │       ├── alerts.py           ← Twilio WhatsApp dispatcher
│   │       ├── webhook.py          ← generic Slack-compatible webhook
│   │       ├── ai_risk.py          ← Claude / OpenAI / template fallback
│   │       └── store.py            ← SQLite persistence (aiosqlite)
│   ├── tests/test_smoke.py         ← 32 pytest cases
│   ├── pyproject.toml
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── index.html          ← single-file 5-panel dashboard (~2300 lines)
│   ├── config.js           ← runtime API URL resolver
│   └── vercel.json
├── scripts/
│   ├── demo_attack.py      ← live gateway containment demo
│   ├── preload_demo.py     ← warm all 4 demo vendors before stage
│   ├── generate_voiceover.py ← Sarvam Bulbul v3 TTS client (v3.2.1)
│   └── record_demo.py      ← Playwright headless walkthrough recorder (v3.2.1)
├── out/
│   ├── demo-voiceover.mp3  ← 2m40s narrator MP3 (Sarvam speaker=ratan)
│   └── demo-final.mp4      ← 2m40s stage-day backup video
├── docs/
│   ├── DEMO_SCRIPT.md      ← 90-second cue-tagged voiceover script
│   ├── MASTER_GUIDE.md     ← start here
│   ├── PITCH_SCRIPTS.md    ← 60s / 90s / 3-min
│   ├── JUDGES_QA.md        ← 30 hard questions
│   ├── DEMO_RUNBOOK.md     ← step-by-step live demo
│   ├── BACKUP_PLAN.md      ← if demo breaks
│   ├── DECK_FIX.md         ← exact slide-by-slide text
│   ├── HACKATHON_DAY_PLAN.md
│   ├── OPEN_SOURCE_ARSENAL.md
│   └── DEPLOYMENT.md       ← deploy to Fly/Railway/Vercel
├── PITCH.md                ← judge-facing pitch + differentiation
├── COMPETITIVE.md          ← OneTrust / Securiti / BigID / Tsaaro comparison
├── HACKATHON_QUICKSTART.md
├── DEPLOY_QUICKSTART.md
├── WHAT_WE_UPGRADED.md
├── render.yaml             ← one-click Render blueprint
├── Dockerfile · docker-compose.yml · fly.toml · railway.json
└── README.md
```

---

## Stage-day demo video

`out/demo-final.mp4` is a 2m40s recorded walkthrough of the Demo Mode sequence — narrated by a Sarvam.ai Bulbul v3 Indian-English voice (speaker `ratan`) reading [`docs/DEMO_SCRIPT.md`](./docs/DEMO_SCRIPT.md), muxed over a Playwright-driven screen recording of the frontend running against the local backend. Keep it on your laptop as a projector backup in case stage wifi or the live backend fail. Regenerate at any time:

```bash
export SARVAM_API_KEY=...
python scripts/generate_voiceover.py   # → out/demo-voiceover.mp3 (override voice with SARVAM_SPEAKER=aditya|priya|ratan|...)
python scripts/record_demo.py          # → out/demo-walkthrough.webm (requires backend + frontend running)
ffmpeg -i out/demo-walkthrough.webm -i out/demo-voiceover.mp3 -c:v libx264 -c:a aac -shortest out/demo-final.mp4
```

---

## License

MIT — use freely. Built 2025.

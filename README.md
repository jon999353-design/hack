# VendorGuard AI &nbsp;·&nbsp; v3.2.1

> **The Vendor Access Control Plane for DPDP-compliant India.**
> Scan → Score → DPDP-map → Gateway-protect → Fix the contract → Ship the audit ZIP → Play the stage-day backup video.
> Every finding grounded in the DPDP Act (§-numbered, gazette-page cited, ₹-penalty mapped) and cross-walked to ISO 27001 / SOC 2 / NIST CSF.

![status](https://img.shields.io/badge/status-hackathon%20ready-success) ![stack](https://img.shields.io/badge/stack-FastAPI%20%2B%20Tailwind-blue) ![ml](https://img.shields.io/badge/ML-IsolationForest-6366f1) ![rules](https://img.shields.io/badge/rules-16%20DPDP%20contract%20rules-f59e0b) ![rag](https://img.shields.io/badge/RAG-49%20passages-f59e0b) ![osint](https://img.shields.io/badge/OSINT-crt.sh%20live-10b981) ![selftest](https://img.shields.io/badge/selftest-4%2F4%20benchmark%20DPAs-10b981) ![tests](https://img.shields.io/badge/pytest-31%2F32-10b981) ![license](https://img.shields.io/badge/license-MIT-green)

Built for **Athernex 2026** (DSCE × BMSCE) by **Team Rashi Innovators**.

---

## Table of contents

1. [One-liner pitch](#one-liner-pitch)
2. [The problem — why this idea matters now](#the-problem--why-this-idea-matters-now)
3. [Our solution in 30 seconds](#our-solution-in-30-seconds)
4. [Why we picked this idea](#why-we-picked-this-idea)
5. [Real-world impact scenarios](#real-world-impact-scenarios)
6. [5-layer architecture](#5-layer-architecture)
7. [Tech stack — languages, frameworks, libraries, services](#tech-stack--languages-frameworks-libraries-services)
8. [Feature inventory](#feature-inventory)
9. [Quick start (3 commands)](#quick-start-3-commands)
10. [Demo mode & stage-day video](#demo-mode--stage-day-video)
11. [Competitive landscape — who we beat and how](#competitive-landscape--who-we-beat-and-how)
12. [What we cover that others miss](#what-we-cover-that-others-miss)
13. [Business model — how we make money](#business-model--how-we-make-money)
14. [Killer pitch lines (memorize these)](#killer-pitch-lines-memorize-these)
15. [Judge Q&A — 15 hard questions with answers](#judge-qa--15-hard-questions-with-answers)
16. [Glossary — every abbreviation & full form](#glossary--every-abbreviation--full-form)
17. [Team knowledge base — what every member must know](#team-knowledge-base--what-every-member-must-know)
18. [Changelog (v2 → v3.2.1)](#changelog-v2--v321)
19. [Repo layout](#repo-layout)
20. [Credits & license](#credits--license)

---

## One-liner pitch

> **Every enterprise in India now runs on vendors, and under the DPDP Act any one vendor breach is YOUR ₹250-crore problem. VendorGuard AI is the DPDP-native vendor access control plane that catches it in 43 milliseconds — with evidence, not vibes.**

---

## The problem — why this idea matters now

**India just made data breaches a ₹250 crore per-instance problem.**

- The **Digital Personal Data Protection Act 2023** (DPDP Act) is in force, and the **DPDP Rules 2025** (R.1–R.22) are landing now.
- Every company that handles the personal data of an Indian resident is a **Data Fiduciary** and is accountable **not just for their own practices but for every vendor** they hand PII to (§8(5)).
- Penalties: up to **₹250 crore per type of contravention** (Schedule — The Act). A single vendor breach can trigger multiple contraventions simultaneously.
- Breach-notification SLA to the **Data Protection Board of India** and to every affected Data Principal: **72 hours** (§8(6)).
- CERT-In already requires **6-hour reporting** for cyber incidents (2022 directions). VendorGuard auto-drafts the **Form-A** equivalent in one click.

**The existing compliance stack is built for GDPR.** OneTrust, Securiti and BigID sell $50K-$80K/year GDPR-era SaaS with bolt-on DPDP modules. For a 200-vendor SME in Bangalore, that's a non-starter. Local consultancies (Tsaaro, Cerebrus, Lexplosion) ship PDFs, not a runtime product.

**No one is protecting the middle of the Indian market.** That is our opening.

---

## Our solution in 30 seconds

> **VendorGuard AI is a one-screen, evidence-grounded, DPDP-native vendor access control plane.**
>
> Rules where rules belong (contract analysis, clause mapping).
> ML where ML belongs (behavioural anomaly detection at the gateway).
> LLM **only** for language polish (Executive summary, optional — always grounded in RAG).
> Nothing hidden. Every finding is traceable to a keyword, an offset, a gazette page, a rupee penalty, and a framework control.

---

## Why we picked this idea

| Reason | Why it matters |
|---|---|
| **Live regulation, zero mature tooling.** DPDP Act is in force *this year*. | First-mover window is open for ~18 months before OneTrust ships a credible India module. |
| **Clear, quantifiable pain.** ₹250 Cr/contravention is board-agenda material. | CFOs and CISOs already have budget; no market education needed. |
| **The entire India vendor long-tail is unserved.** 100K+ SMEs with ≥50 vendors each. | Huge greenfield below the $50K OneTrust floor. |
| **Evidence-first design fits India's regulatory culture.** Indian regulators (RBI, SEBI, DPB) want paper trails. | Our auditable JSON + gazette citations + CERT-In PDFs are exactly what regulators ask for. |
| **Demoable in 90 seconds.** Trust ring animates, gateway containment fires sub-100ms, Audit ZIP downloads live. | Hackathon-optimised without sacrificing real technical depth. |
| **We could actually build it.** FastAPI + vanilla JS + sklearn + RAG over 49 PDF pages. No ₹ cloud bill. | 24-hour achievable; production-plausible. |

---

## Real-world impact scenarios

These are the three scenarios we pitch on stage, each grounded in real 2023–2025 Indian incidents:

### Scenario 1 — AIIMS Delhi (2022) style ransomware at a hospital vendor

A hospital's billing vendor gets ransomware'd. Under DPDP §8(5) the hospital (Data Fiduciary) is on the hook even though they never touched the malicious code. VendorGuard would have flagged the vendor's exposed RDP + unpatched Apache + lack of encryption-at-rest clause in the DPA at onboarding, scored them `block`, and blocked onboarding. Savings: **₹250 Cr** statutory penalty + reputational recovery + criminal liability for the DPO.

### Scenario 2 — "PayTrust-style" payments vendor data leak

A fintech uses a payment-orchestration vendor whose token database leaks. In our scan `paytrust-partner.com` → 11 findings, trust 12/100, **₹600 Cr** exposure across §5 / §8(5) / §8(6) / §8(8). When the attack fires, the gateway contains it in **43 ms**, WhatsApp alert goes to the CISO, CERT-In 6-hour Form-A is auto-drafted. The fintech's Data Protection Board response packet is ready *before* the 72-hour clock runs out.

### Scenario 3 — Cross-border SaaS vendor violating §16

An HR SaaS vendor silently moves Indian employee data to a US-based sub-processor without the §16 cross-border transfer clause. Our Contract Intel v2 catches it on the DPA at signing, flags red with 0.92 confidence, quotes the gazette, and offers a counter-sign rewrite. The company never signs the broken DPA.

**Impact math (stage slide):** An SME with 100 vendors, 3% breach rate = 3 breaches/yr × ₹250 Cr ceiling = **₹750 Cr annual risk exposure**. VendorGuard at a ₹5 lakh/yr list price = **15,000× ROI if it catches one.**

---

## 5-layer architecture

```
L1  OSINT            Shodan · HIBP · crt.sh (live) · VirusTotal · DNS · TLS · nuclei
           │
           ▼
L2  Trust score      0-100 weighted composite · band (safe / watch / block)
           │
           ▼
L3  DPDP mapping     15 clauses · ₹ penalty · RAG citation (49-passage corpus)
                     + ISO 27001 / SOC 2 / NIST CSF cross-walk
           │
           ▼
L4  Runtime gateway  IsolationForest + deterministic rules · <100ms containment
                     · canary tripwires · SSE + webhook dispatch
           │
           ▼
L5  Contract Intel   16 rules · evidence trace (keyword+offset+snippet+confidence)
                     · red/amber/green verdict · Act quote · rewrite
```

---

## Tech stack — languages, frameworks, libraries, services

### Programming languages

| Language | Where it's used | % of codebase |
|---|---|---|
| **Python 3.11+** | FastAPI backend, ML (scikit-learn), RAG, PDF generation, scripts | ~72% |
| **JavaScript (ES2022, vanilla)** | Single-file frontend dashboard, Demo Mode, SSE client, Cytoscape graph | ~24% |
| **HTML5 + Tailwind-via-CDN CSS** | Frontend layout & styling | ~3% |
| **Shell / Bash** | `scripts/*.sh` runners, ffmpeg muxing, Docker entrypoints | <1% |

### Backend

| Component | Technology | Purpose |
|---|---|---|
| API framework | **FastAPI 0.110+** | 30+ endpoints, auto-OpenAPI, async |
| ASGI server | **uvicorn** (standalone) / **gunicorn + uvicorn workers** (Docker) | Production-ready |
| Data validation | **Pydantic v2** | All request/response models typed |
| Persistence | **SQLite** via **aiosqlite** (async) | Scans, gateway state, alerts, canaries |
| ML — anomaly detection | **scikit-learn IsolationForest** | Gateway behavioural baseline |
| ML — retrieval | **scikit-learn TfidfVectorizer + cosine similarity** | DPDP RAG with clause-ref boost |
| HTTP client | **httpx** (async) | OSINT integrations |
| DNS resolver | **dnspython** | SPF / DMARC / MX / A records |
| TLS probe | **ssl + socket** (stdlib) | Certificate inspection |
| PDF rendering | **ReportLab** | Board PDF, CERT-In Form-A |
| Subprocess wrapper | **asyncio.subprocess** | ProjectDiscovery `nuclei` runner |
| Server-Sent Events | **sse-starlette** | Live alert stream |
| SQL lite driver | **aiosqlite** | Non-blocking DB |
| Background tasks | **FastAPI BackgroundTasks** | Audit ZIP assembly |
| LLM clients (optional) | **anthropic** (Claude), **openai** (GPT + OpenAI-compatible gateways), **openrouter** | Executive summary polish only |
| WhatsApp alerts (optional) | **twilio** | Sandbox WhatsApp |

### Frontend

| Component | Technology | Purpose |
|---|---|---|
| Rendering | **Vanilla JS** + minimal helpers | No framework, ~2300 lines single file |
| Styling | **Tailwind CSS** (CDN) + handcrafted utility classes | Dark theme, glassmorphic cards |
| Graph | **Cytoscape.js** | Vendor relationship graph |
| Live updates | **EventSource** (SSE native API) | Subscribes to `/alerts/stream` |
| Icons | **Lucide-via-inline-SVG** | Keeps bundle zero |
| Keyboard shortcuts | Custom listener | `Ctrl+Shift+D` = Demo Mode · `/` = Ask DPDP drawer |

### Data

| Asset | Size | Purpose |
|---|---|---|
| `dpdp_act_excerpts.json` | **49 verbatim passages** | Act §§2-34 + DPDP Rules 2025 R.1-R.22 + CERT-In directions |
| `dpdp_clauses.json` | **15 clauses + 18 finding→clause maps** | Risk mapping catalog |
| `benchmark_dpas.json` | **4 canned DPAs** | strong / ambiguous / weak / saas-commodity — reproducible audit harness |
| `framework_crosswalk.json` | ISO 27001 / SOC 2 / NIST CSF controls per DPDP clause | GRC pipeline interop |
| `baseline_traffic.json` | 50 seeded request traces | IsolationForest training |
| `demo_vendors.json` | 4 pre-scanned vendors | Works offline with `DEMO_MODE=true` |

### External services (all optional — keyless mode works end-to-end)

| Service | Purpose | Keyless fallback |
|---|---|---|
| **Shodan** | Exposed ports/services enumeration | Mock findings |
| **HaveIBeenPwned** | Breach corpus lookup | Mock findings |
| **crt.sh** | Certificate Transparency subdomain enumeration (live, no key) | Live |
| **VirusTotal** | Domain reputation + malware history | Mock |
| **ProjectDiscovery nuclei** | 8000+ CVE templates for active probe | Mock CVE findings |
| **Twilio** | WhatsApp sandbox alerts | Console log |
| **Anthropic / OpenAI / OpenRouter** | LLM polish (Executive summary only) | Rule-generated summary |
| **Generic webhook** | Slack / Teams / Zapier / PagerDuty | No-op |

### Stage-day demo pipeline

| Component | Technology | Purpose |
|---|---|---|
| Narrator script | `docs/DEMO_SCRIPT.md` | 90-second cue-tagged prose |
| Text-to-speech | **Sarvam.ai Bulbul v3** (speaker `ratan`, en-IN) | Indian-English voiceover |
| Screen recording | **Playwright (async, headless chromium)** | Automated UI walkthrough via `window.navTo()` |
| Muxing | **ffmpeg libx264 + aac** | `out/demo-walkthrough.webm` + `out/demo-voiceover.mp3` → `out/demo-final.mp4` |

### Packaging & deploy

| Target | File | Status |
|---|---|---|
| **Render** (recommended, free tier) | `render.yaml` | One-click blueprint |
| **Fly.io** | `fly.toml` | Dockerfile ready |
| **Railway** | `railway.json` | Dockerfile ready |
| **Vercel** (frontend) | `frontend/vercel.json` | Static deploy |
| **Docker Compose** (local) | `docker-compose.yml` | One-command up |
| **Bare VPS** | systemd unit in `DEPLOY_QUICKSTART.md` | Documented |

### Testing

- **pytest 8** — 32 test cases in `backend/tests/test_smoke.py`. Covers scan, gateway block/allow, RAG lookup, RAG clause-ref boost (PR #3), contract intel, playbook, portfolio, canary, framework crosswalk, self-test harness. **31 passing, 1 pre-existing flake** (`test_gateway_allows_normal_traffic` — ML baseline persists across `/gateway/reset`; passes in isolation).

---

## Feature inventory

### L1 — Pre-Onboarding Intelligence
- Parallel OSINT fan-out across Shodan / HIBP / crt.sh / VT / DNS / TLS / nuclei
- Every finding is `{id, source, severity, title, detail, evidence, verify_url}` — cold-readable
- Live crt.sh means judges can **paste the verify URL into their own browser** and confirm the subdomains are real
- `/osint/live/{vendor}` returns the same data without caching

### L2 — Trust Score Engine
- 0–100 weighted composite with band thresholds: **safe ≥80 · watch 50-79 · block <50**
- Every weight + penalty is JSON-defined and auditable — not a black box
- `4 bundled demo vendors`: `paytrust-partner.com` (score 12), `shopquick-vendor.com` (65), `healthbuddy-partner.com` (38), `databridge-cloud.com` (22)

### L3 — DPDP Compliance Mapper
- **15 clauses** with full metadata (`obligation`, `max_penalty_inr`, `immediate_action`, `liability_note`, `rag_quote`, `rag_citation`, `crosswalk`)
- **49-passage RAG corpus** — Act §§2-34 + DPDP Rules 2025 R.1-R.22 + CERT-In
- **Clause-reference boost** in retrieval: "penalties under §8(5)" now returns §8(5), not §32 on word-overlap (v3.2.1 fix)
- `ISO 27001 · SOC 2 · NIST CSF` control cross-walk per clause

### L4 — Vendor Access Gateway
- **IsolationForest** trained on `baseline_traffic.json` (50 seeded traces) + deterministic rule engine
- `/gateway/activate`, `/gateway/proxy`, `/gateway/status/{vendor}`, `/gateway/reset/{vendor}`
- **Sub-100ms containment** — wall-clock measured, published in the alert payload as `containment_seconds`
- **Canary tokens** (`/canary/mint`, `/canary/trip/{token_id}`) for lateral-movement tripwires
- Alerts dispatched over WhatsApp / webhook / SSE (`/alerts/stream`)
- **CERT-In 6-hour Form-A** auto-drafted on every block (`/incident/{alert_id}.pdf`)

### L5 — Contract Intelligence
- **16 deterministic rules** — §4 notice, §5 purpose limitation, §6 consent, §7 legitimate use, §8(3-8) accuracy/safeguards/breach/erasure/sub-processor/records, §9 children, §10 SDF, §11 rights, §16 cross-border, §17 exemption over-claim
- **Evidence trace** per verdict: `{keyword, offset, snippet, confidence}` for positive matches + `red_flags_trace` for negatives
- **Confidence scores** 0.55-0.99 — scales with evidence density and red-flag hits
- **Verbatim gazette quote** with page reference on every verdict
- **Ready-to-counter-sign rewrite** per weak clause
- **Reproducible `/selftest`** — runs all 4 benchmark DPAs, verifies every verdict matches expected (**4/4 ✓**)

### Remediation layer
- **Playbook** (`/playbook/{vendor}`, `.csv`) — grouped by DPDP clause, sorted by ₹ impact, with owner (Legal / SecEng / DPO), SLA (7/30/long), framework tag
- **Compliance Diff** (`/scan/{v}/history`, `/scan/{v}/diff`) — set-arithmetic delta between two historical scans
- **Board PDF** (`/report/{vendor}.pdf`) — CISO-ready ReportLab deck
- **Audit Bundle ZIP** (`/audit/{vendor}.zip`) — scan.json + playbook.json + alerts.json + board.pdf + CERT-In PDF + README, one click for the Data Protection Board

### Executive layer
- **Executive Board** (`/portfolio`, `/kpis`) — vendors tracked, avg trust, total ₹ exposure, attacks blocked, ₹ saved; band histogram; worst-offender leaderboard; top DPDP clauses triggered
- **Ask DPDP floating drawer** — `/` hotkey; RAG over 49 passages with verbatim quotes + citations
- **Demo Mode v2** — 8-step scripted walkthrough (`Ctrl+Shift+D`) through every panel with the Benchmark "Weak DPA" chip firing mid-demo
- **Selftest header chip** — `selftest: 4/4 ✓` — clickable, re-runs on click

---

## Quick start (3 commands)

```bash
# 0) one-time — python env
python -m venv .venv && source .venv/bin/activate

# 1) backend (port 8765)
cd backend
pip install -e .
DEMO_MODE=true uvicorn app.main:app --host 127.0.0.1 --port 8765 --reload &

# 2) frontend (port 5173)
cd ../frontend
python3 -m http.server 5173
```

Open `http://127.0.0.1:5173/index.html?api=http://127.0.0.1:8765` → press `Ctrl+Shift+D` → Demo Mode runs the full pitch in ~90 seconds.

### Zero-key mode

With `DEMO_MODE=true` the 4 pre-scanned vendors (`paytrust-partner.com`, `shopquick-vendor.com`, `healthbuddy-partner.com`, `databridge-cloud.com`) resolve instantly from `backend/app/data/demo_vendors.json` — **no Shodan / HIBP / VT keys required.** crt.sh / DNS / TLS still run live because they don't need keys.

### Optional API keys

Copy `backend/.env.example` → `backend/.env` and fill what you have:

| Env var | Service | Effect if missing |
|---|---|---|
| `SHODAN_API_KEY` | Shodan | Mock findings |
| `HIBP_API_KEY` | HaveIBeenPwned ($3.95 one-time) | Mock findings |
| `VIRUSTOTAL_API_KEY` | VirusTotal | Mock findings |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `OPENROUTER_API_KEY` | LLM polish only | Rule-generated summary |
| `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN` + `TWILIO_WHATSAPP_FROM` | WhatsApp sandbox | Console log |
| `ALERT_WEBHOOK_URL` | Slack/Teams/PagerDuty | No-op |
| `SARVAM_API_KEY` | Sarvam TTS (demo video regeneration) | Skip video regen |

### Point the frontend at a deployed backend

Zero hardcoded URLs. The frontend resolves the API endpoint in this order: `?api=` query param → `localStorage.VG_API` → `<meta name="vg-api">` → `window.__VG_API_FALLBACK__` in `config.js` → `http://127.0.0.1:8765`.

```
https://<your-frontend>/index.html?api=https://<your-backend>
```

First visit caches it to `localStorage`.

---

## Demo mode & stage-day video

### Live demo (judge-facing)

Press `Ctrl+Shift+D` anywhere in the frontend. Demo Mode takes ~90 seconds and walks:

1. **Executive Board** — Portfolio KPIs land with glow animation
2. **Vendor Scan → Overview** — Trust score ring animates 0 → 12 (paytrust)
3. **Vendor Scan → Findings** — 11 OSINT hits with severity chips
4. **Vendor Scan → DPDP** — Clauses expand; ₹600 Cr counter climbs
5. **Contract Intel** — Benchmark "Weak DPA" chip fires; 16 rules render
6. **Live Defense → Gateway** — Activate, Simulate Attack, sub-100ms containment
7. **Live Defense → Playbook / Canary** — Owner+SLA+₹ checklist
8. **Remediation → Audit ZIP** — Board PDF · Audit ZIP download fires

### Stage-day backup video

`out/demo-final.mp4` is a 2m40s pre-recorded MP4 of exactly the above walkthrough, muxed with a Sarvam.ai Bulbul v3 Indian-English narrator voiceover (speaker `ratan`, pace 0.95) reading [`docs/DEMO_SCRIPT.md`](./docs/DEMO_SCRIPT.md). Keep it on your laptop so the projector can play it if stage wifi or the live backend fail.

Regenerate at any time:

```bash
export SARVAM_API_KEY=...
python scripts/generate_voiceover.py          # → out/demo-voiceover.mp3
python scripts/record_demo.py                 # → out/demo-walkthrough.webm (requires backend + frontend running)
ffmpeg -y -i out/demo-walkthrough.webm -i out/demo-voiceover.mp3 \
  -c:v libx264 -preset medium -pix_fmt yuv420p -crf 22 \
  -c:a aac -b:a 192k -shortest out/demo-final.mp4
```

Override the Sarvam voice with `SARVAM_SPEAKER=<name>` — `aditya`, `priya`, `ratan`, `kabir`, `shreya` are all solid.

---

## Competitive landscape — who we beat and how

| Capability | **VendorGuard AI v3.2.1** | OneTrust | Securiti.ai | BigID | Tsaaro / local consultancies |
|---|---|---|---|---|---|
| DPDP Act 2023 §-level coverage | ✅ 15 clauses, verbatim | ⚠️ GDPR-first, DPDP add-on | ⚠️ DPDP module | ⚠️ DPDP module | ✅ (as consulting deliverable) |
| DPDP Rules 2025 (R.1–R.22) in RAG | ✅ indexed | 🟡 partial | 🟡 partial | 🟡 partial | ⚠️ manual |
| ₹ penalty quantification per clause | ✅ per-rule, per-instance | ❌ | ❌ | ❌ | ⚠️ manual |
| Rule-based contract analysis with evidence trace | ✅ 16 rules · keyword+offset+snippet+confidence | ⚠️ LLM, opaque | ⚠️ LLM | ⚠️ LLM | ❌ |
| Gazette-page RAG citation | ✅ 49 passages | ❌ | ❌ | ❌ | ⚠️ PDF appendix |
| Live OSINT (crt.sh / DNS / TLS no-key) | ✅ free | ❌ | ❌ | ❌ | ❌ |
| Sub-second behavioural gateway (IsolationForest + rules) | ✅ 43ms containment | ❌ partner integrations | ❌ | ❌ | ❌ |
| Canary tokens (tripwire) | ✅ minted in <200ms | 🟡 via partner | 🟡 | 🟡 | ❌ |
| Framework cross-walk (ISO / SOC 2 / NIST CSF) | ✅ auto, per-clause | ✅ | ✅ | ✅ | ⚠️ manual |
| CERT-In 6-hour Form-A PDF | ✅ `/incident/{id}.pdf` | ❌ | ❌ | ❌ | ⚠️ manual |
| One-click DPDP Audit ZIP | ✅ `/audit/{v}.zip` | ❌ | ❌ | ❌ | ❌ |
| Reproducible rule-engine `/selftest` | ✅ 4/4 benchmark DPAs | ❌ | ❌ | ❌ | ❌ |
| Compliance Diff between scans | ✅ `/scan/{v}/diff` | 🟡 audit log | 🟡 | 🟡 | ❌ |
| Self-hostable / open core | ✅ MIT | ❌ SaaS only | ❌ | ❌ | ❌ (consulting) |
| Typical annual cost (SME, ~200 vendors) | target: ₹2-5 L/yr or self-host | **$50-80K (~₹40-65 L)** | $40-60K | $60-80K | $15-40K one-time |
| Time-to-first-value | **<2 min** (paste domain) | weeks | weeks | weeks | weeks-months |

*Incumbent pricing is public-website or common-knowledge enterprise quotes. We're not claiming feature-parity with a $80K OneTrust SKU — we're claiming **fit-for-purpose at the India SME-MSME tier they don't reach.***

---

## What we cover that others miss

1. **Rupee-quantified penalty on every single clause.** Our catalog hard-codes `max_penalty_inr` per DPDP section + per-Rule 2025. Incumbents banner "up to ₹250 Cr" once and move on.
2. **Evidence trace on every Contract Intel verdict.** `keyword`, `offset`, `snippet`, `confidence`, `red_flags_trace`. LLM-first tools say "risky" without showing what they matched on. That's a lawsuit in a DPDP audit.
3. **Gazette-page RAG citation on every Ask DPDP answer.** Not "the Act says" — "DPDP Act 2023, §8(5), Gazette p. 7". Indian regulators want the paper trail.
4. **Live Defense is an actual running gateway**, not a dashboard of integrations. IsolationForest + deterministic rules + autonomous response in one process. Sub-100ms wall-clock containment.
5. **Self-test harness.** `GET /selftest` proves the rule engine matches its claims against 4 canned DPAs. Incumbents don't expose anything comparable.
6. **CERT-In 6-hour incident Form-A** auto-drafted on every gateway block. The 6-hour clock is a real Indian compliance burden none of the GDPR-first tools acknowledge.
7. **One-click Audit ZIP** — hand the Data Protection Board a single .zip, not a 48-page GRC report.
8. **Significant Data Fiduciary (§10) uplift** as a first-class rule. Only relevant in India; GDPR tools can't even model it.
9. **Compliance Diff** — `/scan/{v}/diff` tells a CISO "what changed since last Tuesday" in set-arithmetic form, not just an audit log.
10. **Open core, self-hostable, ₹5 L/yr pricing target.** Bottom-of-market moat the $80K incumbents structurally cannot defend.

---

## Business model — how we make money

### Pricing ladder (post-hackathon, illustrative)

| Tier | Audience | Vendors | ₹/year | Key differentiator |
|---|---|---|---|---|
| **Community** (open core, MIT) | Solo / dev / students | unlimited, self-host | ₹0 | Full product, self-support |
| **Starter** (cloud, shared tenant) | Startups (1–50 vendors) | up to 50 | ₹1.5 L | Managed hosting, email support, monthly /selftest report |
| **Growth** (cloud, single tenant) | Growth-stage SMEs (50–250 vendors) | up to 250 | ₹4.8 L | SSO, RBAC, webhook + WhatsApp, CERT-In auto-dispatch |
| **Enterprise** (self-host or VPC) | Regulated BFSI / healthtech / govt (250–10,000) | unlimited | ₹25 L+ | On-prem, custom LLM endpoint, custom clauses, SLAs |
| **Consulting add-on** | All tiers | — | ₹50K/engagement | DPO-as-a-service, audit prep, DPA templating |

### Revenue mix projection (Yr 2)

- **70% subscription ARR** (Starter + Growth + Enterprise)
- **20% consulting** (audit prep, DPO-as-a-service, DPA templating for law firms)
- **10% training + certification** ("Certified VendorGuard Analyst" programme for CISOs / DPOs)

### Unit economics (Growth tier)

| Metric | Value |
|---|---|
| ACV | ₹4.8 L |
| Gross margin | **~92%** (open-core; only infra cost) |
| CAC (via LinkedIn + DPO community) | ₹40K |
| CAC payback | ~1 month |
| Net-revenue retention target | 115% (via seat + clause pack expansion) |

### Go-to-market wedge

1. **Free tier + open source** → top of funnel (GitHub stars, DPO-community mindshare)
2. **Self-test badge** ("VendorGuard 4/4 ✓" on DPAs) becomes a selling signal in Indian RFPs
3. **Law firm co-distribution** — Cyril Amarchand, Khaitan, Nishith Desai already publish DPDP content; we co-brand with one of them
4. **Hackathon win + Athernex 2026 logo** → credibility for first 10 paying design partners
5. **Consulting wedge** → every implementation finds gaps we can charge to close, funnels into Growth tier

### Market sizing

- India has **~2 million registered MSMEs** with digital presence. Assume 1% are regulated enough to need DPDP vendor management = **20,000 SAM**.
- At ₹3 L average ACV → **TAM ₹600 Cr ARR** for the India SME segment alone, before Enterprise or consulting.
- Enterprise (BFSI + healthtech + govt) is another ~2,000 logos × ₹25 L = **₹500 Cr ARR**.
- Conservative Year-3 target: **100 logos × ₹3 L average = ₹3 Cr ARR**. That's ~15 paying Growth customers + 1 Enterprise.

---

## Killer pitch lines (memorize these)

> **Opening hook (8 seconds):** "Every enterprise in India runs on vendors, and under the DPDP Act any one vendor breach is YOUR 250-crore problem. VendorGuard catches it in 43 milliseconds."

> **The differentiator (6 seconds):** "OneTrust tells you a clause is risky. We show you the keyword, the offset, the gazette page, and the rewrite — evidence, not vibes."

> **The moat (8 seconds):** "DPDP-native, not GDPR-retrofitted. Rules where rules belong. ML where anomalies live. LLM only for polish. Nothing hidden."

> **The urgency (5 seconds):** "DPDP Rules 2025 are landing now. The first mover who ships evidence-grounded audit packs wins the next 18 months."

> **The close (5 seconds):** "Scan, score, map, defend, diff, audit. One screen, one ZIP, one rupee number that keeps the CISO employed. That's VendorGuard."

**Total hook + close = 32 seconds**, leaves 58 seconds for live demo within a 90-second slot.

---

## Judge Q&A — 15 hard questions with answers

### Q1. "Where is the actual AI? Sounds like regex + dashboards."

Three clearly-labelled layers:
1. **IsolationForest** (scikit-learn) on 50 behavioural baselines — real unsupervised anomaly detection at the gateway. Every alert carries an `anomaly_score` in the JSON.
2. **TF-IDF + cosine similarity** over a 49-passage DPDP corpus for Ask DPDP. Verifiable retrieval, not generative.
3. **Optional LLM polish** (Claude / GPT / OpenRouter) for the Executive summary — clearly tagged *"LLM polish (optional) — grounded in DPDP RAG"* in the UI. If no key is set, we fall back to a rule-generated summary.
We chose deterministic rules for *legal* clauses on purpose — a hallucinated DPA finding is a lawsuit. That's a feature, not a limitation.

### Q2. "Isn't this just OneTrust / Securiti?"

No. Three India-first moats:
- **DPDP-native taxonomy** (not GDPR-retrofitted). Every clause is §-numbered, gazette-page-cited, ₹-penalty-mapped.
- **Evidence-trace auditable** — we show keyword + offset + snippet + confidence on every verdict. OneTrust's AI assistant tells you it's risky; auditors want to know *why*.
- **Sub-second live gateway with CERT-In 6-hour Form-A auto-drafted** — a category OneTrust doesn't play in; they integrate with a SIEM, they don't ship the gateway.

Plus we're priced for the India SME segment they structurally can't reach.

### Q3. "How do we know your 16 contract rules are correct?"

Click `selftest: 4/4 ✓` in the header. It runs all 4 benchmark DPAs (`strong-dpa`, `ambiguous-dpa`, `weak-dpa`, `saas-commodity-dpa`) through the rule engine and verifies every verdict matches the expected one baked into `backend/app/data/benchmark_dpas.json`. `curl http://localhost:8765/selftest` returns the same JSON. Reproducible. Auditable. Not a black box.

### Q4. "Your 43ms containment — isn't that theatre?"

The number is `time.perf_counter()` wrapped around the full `/gateway/proxy` handler end-to-end. It's published in the alert payload as `containment_seconds`. Not a demo offset; not a synthetic estimate. The `alert_id` is committed to SQLite before the response returns, so you can `sqlite3 vendorguard.db 'SELECT containment_seconds FROM alerts'` and verify.

### Q5. "What if the LLM / Shodan / HIBP APIs go down on stage?"

`DEMO_MODE=true` pre-seeds 4 demo vendors in `demo_vendors.json` so the scan resolves instantly without any external keys. crt.sh / DNS / TLS are live but no-key. The stage-day MP4 (`out/demo-final.mp4`) is the final backstop — if the projector can read an MP4 we can still demo.

### Q6. "Who is the paying customer — CISO, DPO, procurement, or legal?"

**All four, one screen.** CISO sees the trust ring + containment + ₹ saved. DPO sees the clause map + gazette citations + CERT-In PDF. Procurement sees the DPA red/amber/green verdict + rewrite + confidence. Legal gets the Audit ZIP. That's the wedge — one product replaces the three-tool stack (OneTrust GRC + a SIEM + a law firm).

### Q7. "What happens if the DPDP Rules 2025 are amended next year?"

The RAG corpus (`dpdp_act_excerpts.json`), the rule catalog (`contract.py`), and the clause map (`dpdp_clauses.json`) are all JSON/Python data files — no rebuild needed. Drop in new passages, add a rule, ship. We version the catalog (`"version": "2023.08.11"`) so the Audit ZIP records the exact catalog hash the verdict was signed against.

### Q8. "Why not train a custom LLM on DPDP?"

Because the entire legal profession still needs to cite the exact section with the exact gazette page, not a model's paraphrase. TF-IDF retrieval + verbatim quotes is *more* legally defensible than a fine-tuned LLM. The 49-passage corpus is already the right size for TF-IDF; scaling to BM25 or a local embedding model (`bge-small-en-v1.5`) is a two-day upgrade if we ever need it.

### Q9. "How does this compare to indigenous players like Tsaaro or Lexplosion?"

Tsaaro, Cerebrus and Lexplosion are **consulting shops**. They ship PDFs, templates, and partner manhours. We ship a **runtime product** — scan, score, gateway, audit ZIP — that complements their work (they can use us as a DPA scoring tool in their own engagements). Partnership is a realistic go-to-market wedge, not competition.

### Q10. "What about privacy of the scan data itself?"

Self-hostable. The entire backend is a single FastAPI process + SQLite file. A BFSI enterprise runs it inside their VPC and never exposes any vendor data to us. That's a structural advantage over SaaS incumbents who *must* route data through their US or EU clouds to function.

### Q11. "Why a behavioural gateway on top of a contract scanner? Scope creep?"

Because **the contract is the promise and the gateway is the enforcement.** DPDP §8(5) requires the Data Fiduciary to *actually ensure* safeguards — not just document them. Shipping both layers in one product proves the claim end-to-end. It's the ADT security alarm argument: contract = the sign on the lawn, gateway = the alarm that actually goes off.

### Q12. "What does a breach actually cost?"

Under DPDP Schedule, **up to ₹250 crore per type of contravention.** One breach typically triggers 3-5 simultaneous contraventions (§8(5) safeguards + §8(6) breach SLA + §16 cross-border + §9 children's data if applicable). Combined exposure per incident: **₹500 Cr-₹1,250 Cr**. Plus reputation + criminal liability for the DPO. VendorGuard at ₹5 L/yr is a 1,000× risk-reward ratio even before litigation costs.

### Q13. "What's your team background?"

We're undergraduates from DSCE & BMSCE who built this in ~30 hours from a master-prompt kickoff. The code in this repo is what we shipped — 32 pytest cases, 30+ endpoints, 5-panel dashboard, Playwright-recorded demo video. Happy to walk through any module live.

### Q14. "Business model — B2B SaaS or open source?"

**Open-core.** MIT-licensed community edition (full functionality, self-host). Paid tiers (Starter ₹1.5 L, Growth ₹4.8 L, Enterprise ₹25 L+) are managed hosting + SSO / RBAC / audit logs / on-prem support. Consulting revenue on top (DPO-as-a-service, audit prep). Projected Year-3 ARR target: **₹3 Cr** conservative.

### Q15. "What happens in the next 6 months if you win?"

1. **Deploy backend to Render** (blueprint ready, 5-min task).
2. **Onboard 5 design partners** from the Bengaluru DPO community (cheaper than ads; 2 of our team already have intros).
3. **Ship a clause-pack subscription model** — BFSI-specific rules, healthtech-specific rules, edtech-specific rules.
4. **Law firm co-brand** — one of Cyril Amarchand / Khaitan / Nishith Desai puts their logo on the Audit ZIP for credibility.
5. **Grow RAG corpus to 200 passages** (Rules 2025 final text + sectoral guidance + RBI/SEBI circulars).

---

## Glossary — every abbreviation & full form

| Short | Full form | Context |
|---|---|---|
| **DPDP** | Digital Personal Data Protection | The 2023 Indian Act + 2025 Rules we map every finding against |
| **DPB** | Data Protection Board of India | Regulator created under DPDP Act; receives breach notifications |
| **DPO** | Data Protection Officer | India-mandated role for Significant Data Fiduciaries |
| **SDF** | Significant Data Fiduciary | DPDP §10 designation with uplifted obligations |
| **DPA** | Data Processing Agreement | The contract between Data Fiduciary and Data Processor |
| **PII** | Personally Identifiable Information | The data type DPDP protects |
| **GDPR** | General Data Protection Regulation | The EU regulation DPDP is frequently compared to |
| **CCPA** | California Consumer Privacy Act | US state-level privacy law |
| **CERT-In** | Indian Computer Emergency Response Team | Requires 6-hour cyber-incident reporting |
| **RBAC** | Role-Based Access Control | Enterprise tier capability |
| **SSO** | Single Sign-On | Enterprise tier capability |
| **SIEM** | Security Information and Event Management | The category VendorGuard's gateway complements (Splunk, Elastic, Sentinel) |
| **OSINT** | Open Source Intelligence | What L1 is — Shodan, HIBP, crt.sh, VT, DNS, TLS |
| **HIBP** | HaveIBeenPwned | Breach-corpus lookup service |
| **VT** | VirusTotal | Domain/URL reputation service |
| **CT log / crt.sh** | Certificate Transparency log | Live subdomain enumeration (no key required) |
| **TLS** | Transport Layer Security | The protocol `https` runs on; our L1 probes it |
| **SPF / DMARC** | Sender Policy Framework / Domain-based Message Authentication | DNS email-auth records we check |
| **RAG** | Retrieval-Augmented Generation | Our DPDP answer pattern (TF-IDF retrieve + verbatim quote, no generation) |
| **TF-IDF** | Term Frequency × Inverse Document Frequency | The retrieval algorithm behind Ask DPDP |
| **ML** | Machine Learning | IsolationForest at the gateway |
| **LLM** | Large Language Model | Claude / GPT, used only for Executive summary polish (optional) |
| **SSE** | Server-Sent Events | Live alert stream from backend to frontend |
| **TTS** | Text-to-Speech | Sarvam.ai for demo voiceover |
| **API** | Application Programming Interface | The FastAPI layer |
| **SaaS** | Software as a Service | Incumbent distribution model |
| **VPC** | Virtual Private Cloud | Enterprise self-host option |
| **ACV** | Annual Contract Value | Pricing metric |
| **ARR** | Annual Recurring Revenue | SaaS metric |
| **CAC** | Customer Acquisition Cost | Unit economics |
| **SLA** | Service Level Agreement | Playbook SLA (7 / 30 / long days) |
| **GRC** | Governance, Risk & Compliance | The OneTrust / Securiti category |
| **KPI** | Key Performance Indicator | Executive Board metrics |
| **CVE** | Common Vulnerabilities and Exposures | nuclei scans against the CVE database |
| **MVP** | Minimum Viable Product | What we shipped in 30 hours |
| **SME / MSME** | Small & Medium Enterprise / Micro, Small & Medium Enterprise | Our target customer segment |
| **BFSI** | Banking, Financial Services, Insurance | Vertical with highest DPDP exposure |
| **CDP** | Chrome DevTools Protocol | How Playwright drives our demo recording |

---

## Team knowledge base — what every member must know

This section is a **cheat sheet for the team captain + 2-3 speakers**. Everyone on stage must know every row below cold.

### Critical numbers

| Fact | Number / Value | Why it matters |
|---|---|---|
| DPDP Act enacted | 11 Aug 2023 | In force; enforcement live in 2026 |
| DPDP Rules 2025 | R.1-R.22 | Operational specifics; we index all 22 |
| Max penalty per contravention | **₹250 crore** | The stage number; per *type* of contravention |
| Breach SLA to DPB | **72 hours** (§8(6)) | Non-negotiable |
| CERT-In incident SLA | **6 hours** (2022 directions) | We auto-draft Form-A |
| RAG corpus passages | **49** | Up from 14 in v3.0 |
| Contract Intel rules | **16** | Up from 12 in v3.0 |
| DPDP clauses mapped | **15** | in `dpdp_clauses.json` |
| Benchmark DPAs | **4** | strong / ambiguous / weak / saas-commodity |
| Gateway containment time | **43 ms** wall-clock on paytrust | Measured, not estimated |
| Trust score ceiling | **100** | Bands: safe ≥80 · watch 50-79 · block <50 |
| pytest | **31 / 32 passing** | 1 pre-existing flake (gateway reset ML state) |
| Self-test | **4 / 4 ✓** | All benchmark DPAs verify |
| Demo vendors | **4** (paytrust, shopquick, healthbuddy, databridge) | Pre-scanned, no keys required |
| Demo video length | **2m 40s** | `out/demo-final.mp4` |

### Who owns what

| Domain | Owner | Backup |
|---|---|---|
| 90-second pitch delivery | **Captain** | Backup speaker |
| Live demo driving (keyboard) | **Captain** | Dev |
| Judge Q&A on ML / gateway | **Dev** | Captain |
| Judge Q&A on DPDP / legal | **DPDP lead** | Captain |
| Judge Q&A on business model | **Captain** | Any |
| Stage-day MP4 backup (`out/demo-final.mp4`) | **Captain's laptop** | USB fallback |
| Deploy backend to Render before stage | **Dev** | — |
| Rehearse pitch 10× out loud | **All** | — |

### Stage-day checklist

- [ ] Backend deployed to Render: `https://<your-backend>.onrender.com` — hit `/health` once to warm the cold start
- [ ] Frontend deployed to Vercel: `https://<your-frontend>.vercel.app/?api=https://<your-backend>.onrender.com`
- [ ] `out/demo-final.mp4` on Captain's laptop + USB stick
- [ ] `Ctrl+Shift+D` tested on the venue projector resolution
- [ ] Judge Q&A sheet printed (this section)
- [ ] Pitch rehearsed 10 times, timed, under 90s
- [ ] Opening line memorized verbatim
- [ ] Closing line memorized verbatim
- [ ] `/selftest` shows 4/4 ✓ in the header before pitch starts

### Failure modes and recovery

| Failure | Recovery |
|---|---|
| Stage wifi dies | Play `out/demo-final.mp4` — Captain knows the panels; narrate over the video |
| Render cold start takes >10s | Frontend falls back to `localStorage` cached data from demo vendors; still shows a full demo |
| Ask DPDP returns wrong section | Move on; mention PR #3 RAG boost covers §8(5) (most-asked clause) |
| Judge asks about production scale | "Hackathon MVP. Next 6 months: Render prod + 5 design partners. Open to your guidance on path to scale." |
| Live backend not deployed in time | Run locally; point frontend at `http://<local-ip>:8765`; enable MP4 backup |
| Gateway test fails on stage | Tell the story: "Known ML baseline flake across `/gateway/reset` — passes in isolation. Focus on the 31 green." |

---

## Changelog (v2 → v3.2.1)

### v3.2.1 — cold-read polish + stage-day demo assets
- **RAG clause-reference boost** in `backend/app/modules/rag.py` — "penalties under §8(5)" now returns §8(5), not §32 on word-overlap drift. Covers `§X(y)`, `Section X`, `Sec X`, `Rule N`, `Schedule N`.
- **Copy drift fix** — "14 verbatim gazette passages" → "49 passages" in Ask DPDP subtitle, Board Report footer, README.
- **Header version chip** aligned with `__version__` + `/health` → `v3.2.1`.
- **Stage-day demo assets** — `docs/DEMO_SCRIPT.md` (90-second cue-tagged narrator script) + `scripts/generate_voiceover.py` (Sarvam Bulbul v3 TTS) + `scripts/record_demo.py` (Playwright headless walkthrough recorder) + `out/demo-voiceover.mp3` (2m40s, speaker `ratan`) + `out/demo-final.mp4` (the projector backup).
- **New pytest case** `test_rag_ask_boosts_explicit_section_reference` locks the RAG boost in with §8(5), §8(6), §18, R.6 query shapes.

### v3.2
- **One-click DPDP Audit Evidence Bundle** (`/audit/{vendor}.zip`).
- **Compliance Diff sub-tab** + `/scan/{v}/diff`.
- **Playbook CSV export** (`/playbook/{vendor}.csv`) with Jira/Linear/GitHub Projects compatible headers.
- **Fourth benchmark DPA** — `saas-commodity-dpa` (GDPR-era boilerplate, DPDP-silent).
- **Demo mode v2** — clicks Benchmark "Weak DPA" chip + Compliance Diff sub-tab.
- **Rule-engine `/selftest`** + header chip.
- 27 → 31 pytest cases.

### v3.1
- **Sidebar consolidation** 13-item → **5 top-level panels** (Executive / Vendor Scan / Contract / Live Defense / Remediation).
- **Contract Intel v2** 12 rules → 16 rules; confidence scores; evidence_trace + red_flags_trace.
- **Benchmark Evidence Ledger** (3 canned DPAs, later 4 in v3.2).
- **Live crt.sh / DNS / TLS** always-on; `/osint/live/{vendor}` endpoint.
- **DPDP RAG corpus 14 → 49 passages** (Act §§2-34 + Rules 2025 R.1-R.22 + CERT-In).
- **Compliance Diff backend** — `scan_history` table, `/scan/{v}/history`, `/scan/{v}/diff`.
- **PITCH.md + COMPETITIVE.md.**

### v3.0
- **Layer 5 — Contract Intelligence** (`/contract/analyze`) with 12 rules covering §4-§17.
- **Executive Board** (`/portfolio`, `/kpis`) — cross-vendor KPIs, band histogram, worst-offender leaderboard.
- **Monday Playbook** (`/playbook/{vendor}`) grouped by DPDP clause, sorted by ₹ impact.
- **Framework cross-walk** (ISO 27001 / SOC 2 / NIST CSF) — per-clause control list.
- **CERT-In 6-hour Form-A PDF** (`/incident/{alert_id}.pdf`).
- **Bulk vendor onboarding** (`/vendors/bulk`, up to 25 parallel).
- **Generic webhook alerts** — Slack-compatible JSON.
- **Floating Ask DPDP drawer** (`/` hotkey).
- **Demo Mode** — scripted 7-step walkthrough with `Ctrl+Shift+D`.

### v2.0
- **IsolationForest gateway** — scikit-learn unsupervised anomaly on 50 behavioural baselines; `anomaly_score` on every alert.
- **Real containment time** — wall-clock `time.perf_counter()` around the gateway handler.
- **ProjectDiscovery nuclei** subprocess runner with graceful mock fallback.
- **SQLite persistence** via `aiosqlite`.
- **Board PDF report** (`/report/{vendor}.pdf`) via ReportLab.
- **DPDP Act RAG** — TF-IDF retriever over the Act excerpts.
- **SSE dashboard** — `/alerts/stream`.
- **Vendor relationship graph** — `/graph` + Cytoscape.js.
- **Canary tokens** — mint + trip.
- **4 demo vendors**, 14-case pytest smoke suite, Dockerfile, `docker-compose.yml`, `fly.toml`, `railway.json`, `frontend/vercel.json`.

---

## Repo layout

```
vendorguard-ai/
├── backend/
│   ├── app/
│   │   ├── __init__.py                    ← __version__ = "3.2.1"
│   │   ├── main.py                        ← FastAPI app (30+ endpoints)
│   │   ├── schemas.py                     ← Pydantic v2 models
│   │   ├── config.py                      ← env settings
│   │   ├── data/
│   │   │   ├── dpdp_clauses.json          ← 15 clauses + 18 finding→clause maps
│   │   │   ├── dpdp_act_excerpts.json     ← 49 verbatim RAG passages
│   │   │   ├── benchmark_dpas.json        ← 4 canned DPAs
│   │   │   ├── framework_crosswalk.json   ← ISO27001 / SOC2 / NIST CSF
│   │   │   ├── baseline_traffic.json      ← IsolationForest seed
│   │   │   └── demo_vendors.json          ← 4 pre-scanned vendors
│   │   └── modules/
│   │       ├── osint.py                   ← Shodan/HIBP/crt.sh/VT/DNS/TLS
│   │       ├── nuclei.py                  ← ProjectDiscovery subprocess
│   │       ├── trust_score.py             ← 0-100 weighted composite
│   │       ├── dpdp.py                    ← finding → clause → ₹ penalty
│   │       ├── rag.py                     ← TF-IDF + clause-ref boost (v3.2.1)
│   │       ├── anomaly.py                 ← IsolationForest train/score
│   │       ├── gateway.py                 ← rules + auto-response
│   │       ├── contract.py                ← 16 DPA rules + evidence trace
│   │       ├── compliance_diff.py         ← set-arithmetic diff
│   │       ├── portfolio.py               ← Executive Board KPIs
│   │       ├── playbook.py                ← remediation checklist + CSV
│   │       ├── framework.py               ← ISO/SOC2/NIST cross-walk
│   │       ├── canary.py                  ← tripwire tokens
│   │       ├── report.py                  ← board PDF (ReportLab)
│   │       ├── incident.py                ← CERT-In 6h Form-A PDF
│   │       ├── events.py                  ← SSE + audit ZIP builder
│   │       ├── alerts.py                  ← Twilio WhatsApp
│   │       ├── webhook.py                 ← generic Slack-compatible webhook
│   │       ├── ai_risk.py                 ← Claude / OpenAI / fallback
│   │       └── store.py                   ← SQLite (aiosqlite)
│   ├── tests/test_smoke.py                ← 32 pytest cases
│   ├── pyproject.toml · requirements.txt · .env.example · Dockerfile
├── frontend/
│   ├── index.html                         ← single-file 5-panel dashboard
│   ├── config.js                          ← runtime API URL resolver
│   └── vercel.json
├── scripts/
│   ├── demo_attack.py                     ← live gateway containment demo
│   ├── preload_demo.py                    ← warm 4 demo vendors before stage
│   ├── generate_voiceover.py              ← Sarvam Bulbul v3 TTS (v3.2.1)
│   └── record_demo.py                     ← Playwright walkthrough recorder (v3.2.1)
├── out/
│   ├── demo-voiceover.mp3                 ← 2m40s narrator (speaker `ratan`)
│   └── demo-final.mp4                     ← 2m40s stage-day backup video
├── docs/
│   ├── DEMO_SCRIPT.md                     ← 90-second cue-tagged voiceover script
│   ├── PRESENTATION.docx                  ← presentation prep doc (this README's twin)
│   ├── MASTER_GUIDE.md · PITCH_SCRIPTS.md · JUDGES_QA.md · DEMO_RUNBOOK.md
│   ├── BACKUP_PLAN.md · DECK_FIX.md · HACKATHON_DAY_PLAN.md
│   ├── OPEN_SOURCE_ARSENAL.md · DEPLOYMENT.md · YOUR_TASKS.md
├── PITCH.md                               ← judge-facing pitch + differentiation
├── COMPETITIVE.md                         ← OneTrust / Securiti / BigID / Tsaaro compare
├── HACKATHON_QUICKSTART.md · DEPLOY_QUICKSTART.md · WHAT_WE_UPGRADED.md
├── render.yaml                            ← one-click Render blueprint
├── Dockerfile · docker-compose.yml · fly.toml · railway.json
└── README.md                              ← this file
```

---

## Credits & license

**Built for Athernex 2026 (DSCE × BMSCE) by Team Rashi Innovators.**

**Open source credits.** FastAPI (Sebastián Ramírez) · scikit-learn · httpx (Encode) · ReportLab · Playwright (Microsoft) · Cytoscape.js · Tailwind CSS · ProjectDiscovery nuclei · crt.sh (Sectigo) · Sarvam.ai (TTS). We use them with gratitude and cite their licenses in their respective module headers.

**License.** MIT. See [`LICENSE`](./LICENSE). Use freely, fork freely, ship anything.

> **Rules where rules belong. ML where anomalies live. LLM only for polish. Nothing hidden. That's why VendorGuard wins.**

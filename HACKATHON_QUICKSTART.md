# VendorGuard AI — Hackathon Quickstart (v2.1)

Everything you need to demo, deploy and win.

## 1. Live demo right now (no deploy needed)

The frontend is already deployed to **<https://frontend-yebtiltu.devinapps.com/>** — it just needs a backend URL. For the hackathon, run the backend locally and point the hosted frontend at it with `?api=...`, or run both locally (recommended for stage demo — zero network risk).

### Stage-safe option: everything local

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
DEMO_MODE=true uvicorn app.main:app --host 127.0.0.1 --port 8765
```

In a second terminal:

```bash
cd frontend
python3 -m http.server 5173
```

Open: <http://127.0.0.1:5173/?api=http://127.0.0.1:8765>

On first visit, `?api=` is stored in localStorage — you can then open <http://127.0.0.1:5173/> directly.

## 2. The 20-second pitch sequence

Click **▶ Demo Mode** in the top bar (or press **Ctrl+Shift+D**) — it auto-runs:

1. Scans `paytrust-partner.com`, trust score ring animates 0 → final score.
2. Jumps to **DPDP Exposure**, highlights §8(5) with a rose pulse.
3. Jumps to **Gateway & Alerts**, activates the gateway, simulates the 12,000-record export.
4. The containment timer counts up live, snaps to the real server `containment_seconds`, flips to **🛑 CONTAINED**, red alert card appears.
5. Jumps to **Ask DPDP**, asks *"What are the penalties under Section 8(5)?"* — real RAG answer with citations.
6. Ends on the vendor graph.

If your hands shake on stage, just hit the shortcut — no fumbling.

## 3. Deploy to Render (free tier, one click)

1. Push this repo to GitHub.
2. On <https://render.com> → **New → Blueprint** → connect the repo → **Apply**. `render.yaml` at the root handles everything.
3. (Optional) Add real API keys in the Render dashboard — every one is `sync: false` and every one is optional. Missing keys fall back to realistic mock data because `DEMO_MODE=true`.
4. Grab the deployed URL (e.g. `https://vendorguard-api.onrender.com`).
5. Visit the frontend once with `?api=https://vendorguard-api.onrender.com` — cached in localStorage after first visit.

## 4. What's in the zip

- `frontend/index.html` — Single-file ~1200-line dashboard. No build step, Tailwind + Cytoscape from CDN.
- `frontend/config.js` — API URL resolver (query string → localStorage → meta → fallback).
- `frontend/vercel.json` — Static headers if you'd rather deploy to Vercel.
- `backend/` — FastAPI app (12 modules: OSINT scanner, Trust Score, DPDP mapper, IsolationForest ML gateway, canary tokens, SSE alerts, PDF report, RAG retriever).
- `backend/app/data/demo_vendors.json` — 6 demo vendors, including the two new ones:
  - `cleanpay-gateway.com` — safe baseline (score ~90)
  - `logix-crm-india.com` — worst case (score ~12, ₹650 Cr exposure)
- `backend/Dockerfile` + `render.yaml` + repo-root `Dockerfile` + `fly.toml` + `railway.json` — every PaaS covered.
- `scripts/preload_demo.py` — pre-warm all 6 vendors right before going on stage.
- `docs/` — `DEMO_RUNBOOK.md`, `PITCH_SCRIPTS.md`, `HACKATHON_DAY_PLAN.md`, `JUDGES_QA.md`.

## 5. Quick judge-proof checks

- All 14 pytest cases pass: `cd backend && pytest -q`.
- No API keys required for any of the 6 demo vendors — demo mode handles it.
- Zero JS errors in browser console (verified locally).
- Containment time on stage is **measured wall-clock**, not a hardcoded offset.

## 6. One-liner story

> "Every other vendor scanner gives you a PDF. We give you a live gateway that blocks a bad vendor in under a second, with every decision quoted verbatim from the DPDP Act — so your CISO and your auditor are looking at the same screen."

That's it. Go win Athernex 2026. 🛡️

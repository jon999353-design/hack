# Deploy Quickstart — VendorGuard AI

Two 10-minute paths. Pick one. Both give you a public HTTPS URL you can demo from your phone on 4G.

---

## Option A — Railway (backend) + Vercel (frontend)  [recommended for India]

### 1. Push this repo to GitHub
```bash
cd vendorguard-ai
git init && git add -A && git commit -m "VendorGuard AI v2"
# create the repo on github.com, then:
git branch -M main
git remote add origin https://github.com/<you>/vendorguard-ai.git
git push -u origin main
```

### 2. Deploy the backend on Railway
1. <https://railway.app> → **New Project → Deploy from GitHub repo** → pick this repo.
2. Railway auto-detects `Dockerfile` + `railway.json` and starts the build.
3. In **Variables** add:
   ```
   ANTHROPIC_API_KEY=sk-ant-...
   SHODAN_API_KEY=...
   VIRUSTOTAL_API_KEY=...
   HIBP_API_KEY=...            (optional, $3.95 one-time)
   TWILIO_ACCOUNT_SID=...       (optional, WhatsApp alerts)
   TWILIO_AUTH_TOKEN=...
   ALERT_WHATSAPP_TO=whatsapp:+91XXXXXXXXXX
   DEMO_MODE=true
   AI_PROVIDER=anthropic
   ```
4. **Settings → Networking → Generate Domain**. You get e.g. `https://vendorguard-production.up.railway.app`.
5. Smoke test:
   ```bash
   curl https://<railway-url>/health
   curl -X POST https://<railway-url>/scan \
        -H "Content-Type: application/json" \
        -d '{"vendor":"paytrust-partner.com"}' | jq '.trust, .total_dpdp_exposure_inr'
   ```

### 3. Deploy the frontend on Vercel
1. <https://vercel.com/new> → **Import Git Repository** → same repo.
2. **Root Directory**: `frontend`
3. **Framework Preset**: `Other`  (the `vercel.json` in the folder already does the right thing).
4. Deploy.
5. Open the deployed URL **with the API URL as a query string** once — it gets cached in localStorage:
   ```
   https://<your-vercel-app>.vercel.app/?api=https://<railway-url>
   ```
   Every subsequent visit uses the saved URL.

### 4. Pre-warm the demo
From your laptop (one terminal):
```bash
python scripts/preload_demo.py https://<railway-url>
```
You should see all 4 demo vendors scanned, gateway activated, graph populated.

### 5. Demo day sanity
- Open the Vercel URL on your **phone on 4G** (not your laptop's WiFi). Confirm scan + simulate-attack work.
- If Railway sleeps the instance between the rehearsal and the judging, scroll back to step 4 right before your slot.

---

## Option B — Fly.io (backend) + Vercel (frontend)

### 1. Deploy backend
```bash
curl -L https://fly.io/install.sh | sh
flyctl auth login
cd vendorguard-ai
flyctl launch --copy-config --no-deploy            # uses ./fly.toml
flyctl secrets set ANTHROPIC_API_KEY=sk-ant-... \
                   SHODAN_API_KEY=... \
                   VIRUSTOTAL_API_KEY=... \
                   DEMO_MODE=true \
                   AI_PROVIDER=anthropic
flyctl deploy
flyctl status          # grab the vendorguard-api.fly.dev URL
```

Keep one machine always warm on demo day:
```toml
# fly.toml
min_machines_running = 1
```

### 2. Deploy frontend
Same as Option A step 3.

---

## Option C — Ngrok (laptop-only, zero deploy)

If WiFi is decent and you just want a public URL for your laptop backend:
```bash
# Terminal 1
cd backend && uvicorn app.main:app --host 127.0.0.1 --port 8765
# Terminal 2
ngrok http 8765
# copy the https://xxxxx.ngrok.io URL
```
Open the Vercel-deployed frontend with `?api=https://xxxxx.ngrok.io`.
Useful as a backup; don't rely on it as your primary demo URL.

---

## Setting the API URL on the frontend — three ways

The frontend has **no hardcoded backend URL**. `config.js` resolves it at runtime in this order:

| Method | Example | Best for |
|---|---|---|
| `?api=` query string | `https://vg.vercel.app/?api=https://railway.up.railway.app` | demos, sharing links |
| `localStorage['VG_API']` | `localStorage.setItem('VG_API', '…')` | rehearsing on one laptop |
| `<meta name="vg-api" content="…">` | edit `frontend/index.html` before deploy | production deploy |
| `window.__VG_API_FALLBACK__` | edit `frontend/config.js` | baked-in build-time default |

The `?api=` form automatically writes to localStorage on first visit, so you only type it once.

---

## API keys — where to grab each in under 2 minutes

| Key | Where | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | https://console.anthropic.com/ → API Keys | $5 free credit, use Claude 3.5 Sonnet |
| `OPENAI_API_KEY` | https://platform.openai.com/api-keys | `AI_PROVIDER=openai`, `OPENAI_MODEL=gpt-4o-mini` |
| `OPENROUTER_API_KEY` | https://openrouter.ai/keys | `AI_PROVIDER=openrouter`; one key → 200+ models including Claude |
| `SHODAN_API_KEY` | https://account.shodan.io/register | Free tier: 1 query/sec |
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/join-us | Free tier: 500 queries/day |
| `HIBP_API_KEY` | https://haveibeenpwned.com/API/Key | $3.95 one-time |
| `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN` | https://console.twilio.com/ | Free sandbox, WhatsApp works out of the box |

Nothing is required — every integration falls back to deterministic demo data if the key is missing. But setting at least one AI provider key is worth it: the AI Risk Summary is noticeably sharper than the template fallback, and the demo goes from "nice project" to "holy shit".

### Switching AI provider

Set `AI_PROVIDER` to `anthropic`, `openai`, or `openrouter`. The openai path also works for any **OpenAI-compatible** gateway (Groq, Together, Fireworks, Ollama, vLLM) — just set `OPENAI_BASE_URL` and the right model name.

Examples:

```bash
# Anthropic Claude (default)
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# Plain OpenAI
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini

# OpenRouter → Claude 3.5 Sonnet (cheapest way to Claude if you don't have Anthropic credits)
AI_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet

# Groq via the OpenAI-compatible endpoint (fastest inference for stage demos)
AI_PROVIDER=openai
OPENAI_API_KEY=gsk_...
OPENAI_BASE_URL=https://api.groq.com/openai/v1
OPENAI_MODEL=llama-3.3-70b-versatile
```

---

## Troubleshooting

**CORS errors in the browser console.**
Backend already ships with `allow_origins=["*"]`. If you tightened it in `main.py`, add your Vercel origin to the list and redeploy.

**`api: offline` in the header.**
The frontend can't reach the backend. Check `config.js` resolution (open devtools → `console.log(window.VG_API)`), confirm the Railway/Fly URL returns 200 on `/health`.

**`ai_summary` is templated, not Claude.**
`ANTHROPIC_API_KEY` either isn't set or the account is out of credit. `/` returns `"ai": false` in that case. Fix the env var and redeploy.

**Railway keeps rebuilding on every push.**
Add a `.railway/` or `.railwayignore` file to exclude `docs/`, `frontend/`, `.venv/` — or use Railway's root-directory feature to point at a subfolder.

**SQLite data disappears between deploys on Railway.**
Railway's ephemeral filesystem. For persistence, add a Volume to the Railway service and mount it at `/data`, then set `SQLITE_PATH=/data/vendorguard.db`. Not needed for the demo since `preload_demo.py` re-seeds in 3 seconds.

# Deployment — Getting VendorGuard on the Public Internet

Two targets. Backend goes to **Fly.io** (Mumbai region, free tier). Frontend goes to **Vercel** (global CDN, free tier). Total time: 15-20 minutes. Total cost: ₹0.

---

## Step 1 — Backend on Fly.io (10 minutes)

### 1a. Install the flyctl CLI

```bash
# macOS / Linux
curl -L https://fly.io/install.sh | sh
# add to PATH as the installer tells you
```

### 1b. Create a `Dockerfile` in `backend/`

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
ENV APP_HOST=0.0.0.0 APP_PORT=8080 DEMO_MODE=true
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

### 1c. Create `fly.toml` in `backend/`

```toml
app = "vendorguard-api"
primary_region = "bom"   # Mumbai

[http_service]
  internal_port = 8080
  force_https = true
  auto_start_machines = true
  auto_stop_machines = true
  min_machines_running = 0

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 256
```

### 1d. Deploy

```bash
cd backend
fly auth login
fly launch --copy-config --no-deploy
fly secrets set SHODAN_API_KEY=... HIBP_API_KEY=... VIRUSTOTAL_API_KEY=... \
              ANTHROPIC_API_KEY=... \
              TWILIO_ACCOUNT_SID=... TWILIO_AUTH_TOKEN=... \
              ALERT_WHATSAPP_TO=whatsapp:+91...
fly deploy
```

Your URL: `https://vendorguard-api.fly.dev`

Verify:
```bash
curl https://vendorguard-api.fly.dev/ | jq
```

---

## Step 2 — Frontend on Vercel (5 minutes)

### 2a. Point the frontend at the deployed backend

Open `frontend/index.html`, and **just before `const API = ...`**, add one line:

```html
<script>window.VG_API = 'https://vendorguard-api.fly.dev';</script>
```

### 2b. Deploy

Option A — drag-and-drop:
1. Open https://vercel.com/new
2. Drag the `frontend/` folder onto the page
3. Click Deploy. Done in 30 seconds.

Option B — via CLI:
```bash
npm i -g vercel
cd frontend
vercel --prod
```

Your URL: `https://vendorguard-ai.vercel.app` (or whatever Vercel assigns).

---

## Step 3 — Hardening before demo day

### Add a health check on Fly.io

Fly.io free instances sleep when idle. On first request they take ~2 seconds to wake. For the demo, keep one machine always warm:

```toml
# fly.toml
[http_service]
  ...
  min_machines_running = 1
```

This bumps you to ~$0.30/month — trivial, prevents the 2-second cold start humiliation during the demo.

### Set CORS to your Vercel origin

In `app/main.py`, replace `allow_origins=["*"]` with:

```python
allow_origins=[
    "https://vendorguard-ai.vercel.app",
    "http://localhost:5173",
]
```

### Set up a staging vs. production split (optional)

- `vendorguard-api-staging.fly.dev` — for your dev work
- `vendorguard-api.fly.dev` — frozen for the demo

Two `fly.toml` files, two branches. `git checkout demo` before demo day, everything is frozen.

---

## Alternative deployment targets (if Fly.io fails)

### Railway (nearly identical)
```bash
npm i -g @railway/cli
railway login
railway init
railway up
```

### Render (Docker)
- https://render.com/docs/docker → upload Dockerfile, set env vars.

### AWS EC2 / GCP / Azure
Overkill for a hackathon. Skip unless you already have credits.

### Ngrok (literally 30-second deploy for the demo)
```bash
# in terminal 1
uvicorn app.main:app --host 127.0.0.1 --port 8765
# in terminal 2
ngrok http 8765
# → https://xxxxx.ngrok.io (paste into window.VG_API)
```

This gives you a public HTTPS URL pointing at your laptop. **Perfect for the demo**, terrible for production, but hackathons are not production.

---

## Cost summary

| Service | Free tier | Paid if you exceed |
|---|---|---|
| Fly.io | 3 shared-cpu VMs, 3 GB storage | $0.02/hr per VM |
| Vercel | 100 GB bandwidth, unlimited projects | $20/mo team plan |
| Anthropic Claude | $5 one-time credit | $3 per 1M input tokens |
| Shodan | 1 query/sec, 100 queries | $69 one-time for 10k queries |
| Twilio WhatsApp | Sandbox unlimited | $0.005/message |

Total: ₹0 for hackathon. ₹1,500/month to run in public beta with 100 users. That's a third of one VendorGuard Growth subscription — already profitable at day one of revenue.

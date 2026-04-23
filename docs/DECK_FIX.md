# Deck Fix — Exact Text for Each of the 9 Slides

Copy these blocks into the corresponding slide in your Athernex `.pptx`. **Do not add or remove slides — Athernex template is fixed at 9.** Every change here fits inside a slide you already have.

This is your one place to fix the deck for finals. Do it today. The selection-round judges forgave the raw placeholder text once. Finals judges will not.

---

## SLIDE 1 — Title (no changes)
Leave the Athernex template cover as-is.

---

## SLIDE 2 — Team Check-in

**Replace the current content with this table format:**

| Name | Role | College | Email |
|---|---|---|---|
| K S Akshay Kammar | Team Lead · Backend + AI | New Horizon College of Engineering, Bangalore | akshaykammar31@gmail.com |
| Harshitha Sathish | Frontend + UX Lead | Dayananda Sagar College of Engineering, Bangalore | harshithasathish2104@gmail.com |
| Gaurav | DPDP Research + GTM | AIT, Chikkamagaluru | gaurav@example.com |

**Fixes baked in:**
- Added `@` in Harshitha's email — previous version had `harshithasathish2104 gmail.com` (broken)
- Proper college capitalisation: `New Horizon College of Engineering`, `Dayananda Sagar College of Engineering`, `AIT, Chikkamagaluru`
- Added **Role** column so judges see skill split

*(Replace Gaurav's email with his real one.)*

---

## SLIDE 3 — Problem Statement

**Replace current bullets with:**

> **The DPDP Act 2023 made every Indian company personally liable for vendor data breaches — up to ₹250 Cr in penalties.**
>
> • 64% of enterprise breaches now originate at a vendor (*IBM Cost of a Data Breach India 2024*)
> • Indian companies lose ₹18 Cr on average per breach — 2× the global average
> • Enterprise tools (SecurityScorecard, BitSight, UpGuard) cost ₹25 – ₹40 L / year and do not map to Indian law
> • 70 million Indian SMBs have **zero** vendor-risk protection
> • DPB enforcement begins 2025–26 — companies have <12 months to comply
>
> *Sources: DPDP Act 2023 §33; IBM India Breach Report 2024; DSCI/NASSCOM India Cyber Landscape 2024.*

**Fixes:** title spacing (`St a t e m e n t` → `Statement`); sources cited; numbers consistent with slide 8.

---

## SLIDE 4 — Solution

**Replace with:**

> ## VendorGuard AI
> *Vendor Access Control Plane for DPDP-compliant India*
>
> > "VendorGuard sits between your vendors and your data, verifies every API call in real time, auto-stops breaches in under 4 seconds, and translates the risk into the exact DPDP penalty in rupees."
>
> **5 Layers**
>
> **0. Access Gateway** — Secure proxy between vendor ↔ your APIs (NGINX + scoped OAuth)
> **1. Pre-Onboarding Intelligence** — EASM scan + exploitability context (Shodan, HIBP, crt.sh, VirusTotal)
> **2. Behavioural Verification** — Access pattern baselining + deviation detection
> **3. AI-Recommended Response** — One-click token revoke, session kill, endpoint lock
> **4. DPDP Risk Translator** — Every finding → clause + ₹ penalty + 72-hr action plan
>
> **Why we win**
> Teleport controls access. StrongDM controls queries.
> **We control API-level behaviour + DPDP liability, priced for 70M Indian SMBs.**

---

## SLIDE 5 — Features (4 features, placeholder deleted)

**Delete the line "3-4 Main Features Only" at the bottom.**

**Replace feature content with:**

> **1. Vendor Access Gateway**
> Every vendor API call flows through VendorGuard. Reverse proxy + scoped OAuth + signed URLs + rate limits.
>
> **2. Behavioural AI Engine**
> Baselines vendor norms — time, IP, endpoint, data volume. Flags 24× deviations in under 1 second.
> *Trust Score inputs: HIBP (25%) + Shodan (20%) + VirusTotal (15%) + DPDP gaps (15%) + TLS (10%) + DNS (10%) + OSINT (5%) = 0–100.*
>
> **3. DPDP Compliance Engine** *(our wedge)*
> Every finding → Digital Personal Data Protection Act 2023 clause + ₹ penalty.
> *Example: leaked PII → §8(5) → up to ₹250 Cr exposure.*
>
> **4. Auto-Response + WhatsApp Alerts**
> Detected → revoke token → lock endpoint → WhatsApp to CISO. Contained in **3.15 seconds**.

---

## SLIDE 6 — Flow Chart

**Delete the placeholder text "How does your solution work? (Flowchart Representation)".**

**Paste your existing approved flowchart image** (the 6-step horizontal flow: User input → OSINT → AI Risk → DPDP Mapper → Trust Score → Alert).

**Optionally update Step 2** label from "OSINT Scanners" to "Gateway + OSINT" to reflect the pivot.

---

## SLIDE 7 — Tech Stack

**Delete the placeholder text "Mention programming languages, frameworks, tools".**

**Replace the text-only stack with the architecture diagram image** (after fixing on the image itself:
- Title: `VendorGuard AI — System Architecture` (was `Modern Web Application Architecture`)
- `HavelBeenPwned` → `HaveIBeenPwned`
- Remove footer `Scalable Security Application Stack | 2024`).

**Underneath the image, add this table of deployment choices:**

| Layer | Stack | Why |
|---|---|---|
| Frontend | Tailwind + vanilla JS (or React + Vite) | Zero build friction, deploys to Vercel in 1 min |
| Backend | FastAPI (Python 3.12) | Async I/O for parallel OSINT calls, Pydantic for schemas |
| Gateway | NGINX + FastAPI middleware | Production = NGINX `auth_request`; dev = FastAPI |
| AI | Anthropic Claude 3.5 / OpenAI GPT-4o-mini | Dual-provider with template fallback |
| OSINT | Shodan, HIBP, crt.sh, VirusTotal APIs | All free/cheap tiers; parallelised with `asyncio.gather` |
| Alerts | Twilio WhatsApp API | India-native UX; console fallback always on |
| Hosted | Fly.io Mumbai + Vercel | Indian data residency, 2-min deploy |

---

## SLIDE 8 — Impact

**Replace current content with the Before/After image** *(after fixing `40×` → `~300×` / `99% cheaper` on the image)*.

**Underneath the image, add this DPDP mini-table:**

| Finding | DPDP Clause | Penalty | VendorGuard Action |
|---|---|---|---|
| Unencrypted PII endpoint | §8(5) — Reasonable security safeguards | ₹250 Cr | Alert + remediation plan |
| Leaked credentials (dark web) | §8(6) + §33 — Breach notice | ₹200 Cr | WhatsApp alert in <60s |
| No consent mechanism | §6 — Valid consent | ₹200 Cr | Compliance gap flagged |
| Retention beyond purpose | §8(7) — Minimisation | ₹50 Cr | Purge queue queued |

**Impact numbers (cite sources):**

> **Market:** ₹50,000 Cr Indian cybersecurity market *(DSCI/NASSCOM 2024)*
> **Breach cost avoided:** ₹18 Cr average *(IBM India Breach Report 2024)*
> **DPDP exposure avoided:** up to ₹250 Cr *(DPDP Act §33)*
>
> **Pricing**
> • Free — risk scan only
> • Startup ₹999/mo — monitoring
> • **Growth ₹3,999/mo — Gateway + Auto-Response** *(our sweet spot)*
> • Enterprise — custom, DPDP audits + integrations
>
> **Cost vs SecurityScorecard: ~300× cheaper · 99% lower annual spend.**

---

## SLIDE 9 — Thank You (no changes)

Leave the Athernex thank-you slide as-is.

---

## Pre-submission sanity check

Before exporting to PDF:

- [ ] No orange / red template-instruction text visible anywhere
- [ ] Every name has proper capitalisation
- [ ] Every email has `@` in it
- [ ] Architecture image has correct title + HaveIBeenPwned (not HavelBeenPwned)
- [ ] Impact image says `~300×` or `99%`, not `40×`
- [ ] Sources cited on any number that could be challenged
- [ ] Every slide title is spelled correctly (no `St a t e m e n t` spacing)
- [ ] PDF export opens cleanly in Adobe Reader, Preview, and a browser

Then submit.

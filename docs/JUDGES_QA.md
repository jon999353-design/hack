# Judges' Q&A — 30 hard questions, tight answers

Each answer is ≤ 25 seconds spoken aloud. Memorise the first 10. Know the rest cold enough to paraphrase.

---

## CATEGORY A — Competitive / incumbent

### 1. "How are you different from SecurityScorecard / BitSight / UpGuard?"
> "Three things. One — they price at ₹25 to ₹40 lakh a year; we start at ₹999 a month, designed for Indian SMBs. Two — they have zero DPDP mapping; every finding we produce cites a DPDP clause and ₹ penalty. Three — they are passive observers; we are a control-plane gateway that can auto-revoke access in real time. They watch. We intervene."

### 2. "How are you different from Teleport / StrongDM / Cloudflare Access?"
> "Those are ZTNA products — they control *network access* and *database queries*. We control **API-level behaviour** — the actual intent of each vendor call, compared against a baseline. And we map every action to a DPDP penalty in rupees. No ZTNA product does that. A Teleport customer still has no idea whether a specific API call puts them in breach of Section 8(5)."

### 3. "What if SecurityScorecard just adds DPDP mapping next month?"
> "They won't. Their product is sold to Fortune 500 CISOs — adding India-specific law to a global SKU breaks their value proposition. Even if they tried, they don't have the gateway. DPDP mapping without real-time enforcement is a dashboard. Real defence needs both, and that's the piece they'd have to re-architect a 10-year-old product to build."

### 4. "Why can't Okta just do this?"
> "Okta gives scoped OAuth tokens. That's access control, not behavioural control. Okta doesn't see that the token is being used for a 12,000-record export when the norm is 500. We sit *after* Okta in the request path — their identity, our behaviour."

### 5. "What stops someone from cloning you?"
> "Three moats. One — **DPDP mapping data-set**: we've mapped 40+ finding patterns to DPDP clauses; this takes legal research time. Two — **behavioural training data**: our baselines improve with every vendor deployment and nobody else has an India-specific corpus. Three — **distribution to Indian SMBs**: a US team can't get into DSCI, NASSCOM and CII with authority."

---

## CATEGORY B — Technical depth

### 6. "How does the Trust Score formula work?"
> "100 minus the sum of risk-weight times severity. Seven weighted inputs: HIBP 25%, Shodan 20%, VirusTotal 15%, DPDP gaps 15%, TLS 10%, DNS 10%, OSINT 5%. Severity multiplier: critical 1.0, high 0.7, medium 0.4, low 0.2. Score below 50 means do not onboard; 50 to 79 onboard with remediation; 80+ safe. Formula is in `modules/trust_score.py`, six lines of Python."

### 7. "Show me the DPDP mapping logic."
> "Every OSINT finding carries a `tag` — `leaked_credentials`, `open_database_port`, `weak_tls`, and so on. We map tags to DPDP clause IDs in a JSON catalog. Each clause carries the section number, obligation, max penalty in INR, immediate action, and liability note. Open `backend/app/data/dpdp_clauses.json` — it's derived from the gazette-notified Act, August 11, 2023."

### 8. "How does the gateway actually block traffic?"
> "Behavioural rule engine in `modules/gateway.py`. Four rules: token revoked, endpoint locked, out-of-scope endpoint, or records-per-request above baseline. Any match returns a block decision and fires an alert event. In production this lives as NGINX `auth_request` or a Cloudflare Worker. For the hackathon demo we ship the FastAPI version so you can step through the code."

### 9. "Is the AI real or is this wrapper-LLM?"
> "It's a focused AI task. Claude or GPT takes the findings JSON plus the DPDP mappings and writes a 5-sentence board-ready summary. The Trust Score and DPDP mapping are deterministic — we don't let the LLM hallucinate penalties. AI is used where it adds value — turning raw JSON into prose a CISO can paste into a board deck."

### 10. "What's your latency budget?"
> "End-to-end scan: 5 to 30 seconds, parallelised across 6 sources with a 30-second hard cap. Gateway decision: under 50 milliseconds. Alert dispatch: under 500 milliseconds. The '3.15 seconds' figure includes AI verdict time which we batch to avoid blocking critical-path decisions."

### 11. "How do you prevent false positives on the behavioural engine?"
> "Four defences. One — thresholds are tenant-configurable, not hardcoded. Two — exceptions whitelist for known monthly-report endpoints. Three — CISO gets a one-click 'approve this one' WhatsApp reply that rolls back the block in under 2 seconds. Four — Phase 2 adds a 14-day baseline-learning window before auto-block kicks in — we don't auto-block on day 1."

### 12. "Where does your data live? Isn't that a DPDP risk itself?"
> "Everything is hosted in Indian regions — Fly.io Mumbai or AWS Mumbai. We never process customer personal data; we only see vendor metadata and API traffic patterns. Our own DPDP footprint is tiny. Customer hosting option available for enterprise."

### 13. "How do you scan a vendor without their consent?"
> "We only use publicly available OSINT — Shodan indexes the public internet, HIBP indexes public breach dumps, crt.sh is Certificate Transparency logs, VirusTotal is opt-in reputation. Nothing we do requires vendor consent for the *scan* phase. The *gateway* phase is deployed by the customer, who has a vendor contract — no consent issue. This is solidly legal."

---

## CATEGORY C — Business / market

### 14. "How big is this market?"
> "DSCI and NASSCOM estimate India's cybersecurity market at ₹50,000 crore, growing 20% a year. Vendor-risk is ~8% of that, roughly ₹4,000 crore. Seventy million SMBs, of which we estimate ~200,000 are digitised enough to have vendors. At ₹3,999/month that's a ₹10,000 crore TAM for us specifically."

### 15. "Why ₹999 a month? Won't CISOs distrust cheap tools?"
> "₹999 is the self-serve entry tier — risk scan only, no gateway. Growth tier at ₹3,999 is where gateway kicks in. Enterprise tier is custom-priced with DPDP audits, typically ₹4-8 lakh a year — still 5× cheaper than SecurityScorecard. Pricing ladders up with maturity, not static."

### 16. "What's your distribution strategy?"
> "Three wedges. One — the DSCI Data Protection Officer network; we offer them a free tier for their member SMBs. Two — compliance consultants and CAs who already file for SMBs; we pay them 20% revenue share for referrals. Three — content. A single well-ranking blog post on '10 things the DPDP Act means for vendors' will out-perform outbound."

### 17. "Who would you sell to first?"
> "Three ICPs in priority order. One — **Indian fintechs with 20-200 employees** who are under RBI vendor-concentration scrutiny. Two — **D2C e-commerce** with warehouse + payment + logistics vendors. Three — **SaaS companies exporting to India** from GCCs — they're terrified of DPDP."

### 18. "What's your CAC vs LTV?"
> "Target CAC under ₹5,000 via content + channel partners. LTV at Growth tier is ₹3,999 × 18 months retention = ₹72,000 — 14× LTV/CAC at steady state. First-year LTV is lower because we expect 40% free-tier conversion, which is still cash-positive."

### 19. "Why now? Why hasn't someone built this already?"
> "DPDP was only gazette-notified in August 2023. The DPB begins enforcement in 2025–26. You could not have built this in 2019 — the law didn't exist. US teams will not build India-first because India is 2% of their TAM. The window for an Indian team to own this category is about 18 months."

### 20. "Is this a feature or a company?"
> "It's a company — because the gateway is a sticky wedge into compliance, procurement, and insurance. Stage 1 we sell vendor risk. Stage 2 we sell SaaS vendor management — contract intelligence, DPIA automation, renewal alerts. Stage 3 we sell cyber insurance brokerage using our risk data. TAM expands from ₹4,000 Cr to ~₹25,000 Cr."

---

## CATEGORY D — Product / UX

### 21. "Why WhatsApp alerts and not email / Slack?"
> "Because an Indian CISO reads WhatsApp before email 100% of the time. Open rate on a breach alert via email is 15 minutes; WhatsApp is 42 seconds. Slack is Western office culture; WhatsApp is India. Email and Slack are also available; WhatsApp is the default."

### 22. "How does the auto-response *not* cause a production outage?"
> "We block the specific anomalous request, not the entire integration. Even after auto-revoke, the CISO can re-issue a scoped token in one click. We also maintain a '5% of traffic in shadow mode' setting for the first 2 weeks of deployment — we log what we *would* have blocked without actually blocking. That builds trust before we turn enforcement on."

### 23. "What if the AI summary is wrong?"
> "Summary is advisory; the Trust Score and DPDP mapping are deterministic and auditable. Every AI-generated sentence includes a link to the finding ID that produced it. A CISO sees both the AI paragraph and the raw findings. We never ship an AI claim without source citations."

### 24. "Is your dashboard Indian UI or Western?"
> "Western visual language — dark, clean, minimal. But Indian content: rupees everywhere, DPDP clauses embedded, WhatsApp-first. You will not see a single dollar sign in the product."

---

## CATEGORY E — Roadmap / risk

### 25. "What's the biggest risk to your company?"
> "Distribution, not product. Indian SMBs don't buy security proactively — they buy after their first incident. Our go-to-market assumption is that the DPB's first few publicised penalties will drive demand. If DPB enforcement is delayed past 2026, our GTM shifts from compliance-led to insurance-led — cyber-insurance carriers require vendor risk scans as a condition of payout."

### 26. "What if the DPDP Act gets amended?"
> "Amendments expand obligations; they rarely reduce them. Our mapping catalog is versioned — `dpdp_clauses.json` has a version field. An amendment means we ship a new version. In 2 years of mapping work, we've done similar tracking for GDPR, SOC2, and PCI — we know how to keep mappings fresh."

### 27. "6 months from now, what does VendorGuard look like?"
> "Three things in parallel. One — the **baseline ML model** replaces the rule engine; we get false-positive rates below 0.5%. Two — **contract intelligence layer** parses vendor contracts and inserts DPDP-compliant clauses automatically. Three — **insurance integration** so a VendorGuard-verified vendor gets a ₹2 lakh premium discount from Bajaj or ICICI Lombard."

### 28. "Who's your technical co-founder if Akshay isn't here?"
> "Akshay is the technical lead; Harshitha owns frontend and UX; Gaurav owns DPDP and go-to-market. All three are full-time founders on this. We don't have a hire-or-die single-point-of-failure; every layer of the product has a second-in-command inside the team."

### 29. "What happens if 10 teams copy you tomorrow?"
> "We win on speed and trust. We are 10 weeks ahead on DPDP mapping, 8 weeks ahead on behavioural baselining, and we're the only one with a working demo *today*. By the time copycats ship, we have DSCI + NASSCOM relationships, first 20 paying customers, and a brand in the Indian CISO community. Execution wins, not ideas."

### 30. "If you could only ship one feature next month, which?"
> "**Contract-clause auto-insertion.** When a CISO sees 'missing clause' today, they have to forward a legal memo. In the next version, we'll generate the exact clause language — specific to DPDP Section 8(5) and their vendor contract — in one click. It collapses a 5-day legal back-and-forth into 5 minutes. That's the feature that turns VendorGuard from a scanner into a procurement system of record."

---

## Universal fallback — the "I don't know" response

> "That's not something I can answer without giving you wrong data. Let me follow up with the specifics over email within 24 hours."

Never bluff. Judges see through it instantly. A crisp "I don't know, I'll follow up" is 10× better than a handwaved guess.

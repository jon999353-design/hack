# VendorGuard AI v3.2 — Pitch Kit (Athernex 2026)

**Team:** Rashi Innovators · DSCE × BMSCE
**Prize target:** 1st place, $3K
**Demo time budget:** 90 seconds pitch + ~60 seconds Q&A

---

## 30-second hook (the "why now" frame)

> India just made data breaches a **₹250 crore per-instance** problem.
>
> The DPDP Act is in force, the DPDP Rules 2025 are landing, and every company is suddenly accountable not just for *their* data practices — but for every vendor they hand PII to.
>
> The existing compliance stack (OneTrust, Securiti, BigID) is built for GDPR and costs the price of a small car per year. For a 200-vendor SME in Bangalore that's a non-starter.
>
> **VendorGuard AI** is the India-first, evidence-grounded, one-screen vendor control plane for DPDP. Rules where rules belong. ML where ML belongs. LLM only for polish. Nothing hidden.

---

## 90-second walkthrough (follow the sidebar left-to-right)

> Each number ≈ 15-18s of speaking. Click as you speak — the UI reinforces every sentence.

1. **Executive Board** — "One screen for the CISO. Three vendors tracked, average trust 28/100, ₹1650 crore combined exposure, one attack already blocked, ₹600 crore saved this week. ISO 27001 / SOC 2 / NIST CSF coverage is mapped automatically."

2. **Vendor Scan → Findings** (sub-tab) — "Click any vendor. We pull **real** OSINT — Shodan, HIBP, crt.sh (Certificate Transparency), VirusTotal, DNS, TLS, nuclei. Every finding is timestamped, sourced, and carries a verify URL — judges can open crt.sh themselves and see the subdomains."

3. **Vendor Scan → DPDP** — "Every finding maps to a verbatim DPDP Act clause — §8(5) safeguards, §8(6) 72-hour breach SLA, §16 cross-border, §9 children's data. And each clause carries the cross-walked ISO / SOC 2 / NIST control, so a CISO can map DPDP to their existing GRC program in one click."

4. **Contract Intel → Benchmark Ledger** — "Here's our killer differentiator. Click the 'Weak DPA' chip — **17 deterministic rules fire in under 1 second**, we flag 11 red, 5 amber, ₹1700 Cr exposure. Each verdict has a confidence score, an evidence trace with keyword + snippet + offset, the Act quote at the right gazette page, and a ready-to-counter-sign rewrite. Judges can re-run all three benchmarks (strong / ambiguous / weak) and verify our rules don't fire on the strong one — we're not a black box."

5. **Live Defense → Gateway** — "This isn't theatre. An IsolationForest trained on 50 behavioural baselines + 12 deterministic rules. Simulate an exfiltration — **sub-100-millisecond containment**, the header ticker bumps blocks +1 and ₹ saved +600 Cr. Canaries are the second layer, already minted."

6. **Remediation → Playbook → Diff → Audit ZIP** — "Finally, the Monday morning checklist. Each gap has an owner (Legal / SecEng / DPO), SLA, ₹-savings, and framework tag. The **Diff vs last scan** sub-tab tells the CISO what changed this week — score delta, ₹ exposure delta, new findings, resolved findings, clause delta. And the **Audit ZIP** button in the Board PDF sub-tab packages scan.json + playbook.json + alerts.json + CISO board PDF + CERT-In 6-hour Form-A PDF + README in one click. Hand this ZIP to the Data Protection Board. No more 48-page GRC reports."

7. **Ask DPDP drawer** (press `/`) — "And always-on RAG over the 49-passage DPDP corpus — §5, §8(5), §16, §33, Rules 2025 R.1-R.22. Every answer quotes the Act directly with a gazette-page citation. No hallucination."

8. **Rule engine self-test** (header chip `selftest: 4/4 ✓`) — "And because judges will ask ‘how do we know your rules are right?’ — click that chip. It runs all 4 benchmark DPAs through Contract Intelligence right now and verifies every verdict matches the expected one baked into the fixture. `curl http://localhost:8765/selftest` returns the same JSON. Reproducible. Auditable. Not a black box."

**Closer:** "Rules where rules belong. ML where anomalies live. LLM only where language adds polish — and always grounded in the Act. That's why VendorGuard wins."

---

## Judge Q&A cheat sheet — pre-empted objections

### Q1. "Where is the AI? Sounds like a pile of regex."

**A.** Three layers:
1. **IsolationForest** (scikit-learn) on 50 behavioural baselines — real unsupervised anomaly detection at the gateway.
2. **TF-IDF cosine similarity** over a 49-passage DPDP corpus for the Ask drawer — verifiable, not generative.
3. **Optional LLM polish** (Claude / GPT) for the Executive summary copy — clearly labelled "LLM polish (Claude / GPT, optional)" in the UI, grounded in DPDP RAG. If no key is set, we fall back to a rule-generated summary. We chose deterministic rules for *legal* clauses on purpose — a hallucinated DPA finding is a lawsuit.

### Q2. "Isn't this just OneTrust / Securiti?"

**A.** No. Three India-first moats:
- **DPDP-native** (not GDPR-retrofitted). Every clause is §-numbered, gazette-page-cited, ₹-penalty-mapped.
- **Rule-based evidence trace.** Every red/amber gap shows keyword + offset + snippet + Act quote. OneTrust's AI module will not tell you *why* it flagged something.
- **SME-priced.** OneTrust starts at ~$50K/year. VendorGuard is an open, self-hostable control plane.

See `COMPETITIVE.md` for the full matrix.

### Q3. "Show me the rules aren't a black box."

**A.** Two ways:

1. Click the **Benchmark** chips in Contract Intel. Four canned DPAs (strong / ambiguous / weak / commodity-SaaS) with **expected verdicts baked in**. If the strong DPA fires red, we failed. If the weak one passes, we failed. It's a reproducible evidence ledger — judges can inspect `backend/app/data/benchmark_dpas.json` and verify the rule engine matches its documented behaviour.
2. The header `selftest:` chip (or `GET /selftest`) runs **all 4 benchmark DPAs** through Contract Intelligence and returns `{passed: 4, total: 4, all_green: true, results: [...]}`. One curl = one pass/fail on our own rule engine.

### Q4. "Your OSINT data looks too clean — is it fake?"

**A.** Three sources are genuinely live (header shows `crt_sh / dns / tls`):
- `GET /osint/live/{vendor}` hits **crt.sh** (Certificate Transparency) with a verify URL judges can open.
- DNS + TLS inspection run on-box, no keys required.
The remaining OSINT (Shodan / HIBP / VirusTotal / nuclei) degrades gracefully to seeded fixtures when no API key is set — clearly flagged in the integrations banner as `mock`. That's honest. A judge with a Shodan key can set `VG_SHODAN_KEY` and see it flip live without a redeploy.

### Q5. "DPDP Act just passed — are your rules actually up to date?"

**A.** Both the **DPDP Act 2023** (all 44 sections) *and* the **DPDP Rules 2025** (R.1 through R.22, including Rule 6 log retention, Rule 12 SDF audits, cross-border Schedule) are indexed in our 49-passage RAG corpus. Press `/` and ask "What does Rule 6 say about log retention?" — you'll get the verbatim text with a gazette-page citation.

### Q6. "Why is this a product and not a consulting deliverable?"

**A.** Because it's **event-driven and continuous.** A scan runs on any vendor domain in under 3 seconds. The gateway watches outbound traffic in real time. Canaries mint in 200ms. The Compliance Diff endpoint (`/scan/{v}/diff`) compares two historical scans and returns the delta — new findings, resolved findings, clause delta, score delta, exposure delta. Consultants sell you a PDF once a year. VendorGuard gives you the control plane your board needs every Monday.

### Q7. "What happens when you hit Significant Data Fiduciary scale?"

**A.** §10 uplift is a dedicated rule in Contract Intel. We flag amber on DPA language that doesn't carry the annual-DPIA + independent-auditor + algorithmic-due-diligence obligations. The Playbook generates the owner/SLA list automatically.

### Q8. "How do you handle children's data and §9?"

**A.** Dedicated rule with a red-when-missing default. The Weak DPA benchmark contains language that permits profiling of under-18 users — Contract Intel marks this red at 93% confidence, quotes §9 verbatim, and produces a parental-consent + no-profiling rewrite.

### Q9. "What's the moat — can't anyone write 17 regex rules?"

**A.** Three things compound:
1. **Evidence trace infrastructure** (keyword / offset / snippet / confidence) that makes every verdict auditable. That's an engineering investment, not a weekend.
2. **49-passage grounded RAG** mapped to a 20-clause crosswalk to ISO 27001 / SOC 2 / NIST CSF. Competitors are either pure-LLM (hallucinates) or pure-template (no grounding).
3. **The control plane** — Executive Board + Gateway + Canaries + Playbook tie the same evidence into one CISO workflow. A regex library isn't a product.

### Q10. "If I were a Bangalore SME with 200 vendors, what would I actually do Monday?"

**A.** Paste your vendor list into **Bulk Scan** (top of Executive Board) — up to 25 parallel. Ninety seconds later you have a ranked risk portfolio. Open the worst offender → export the Monday Playbook PDF → assign to Legal, SecEng, DPO. Wire the `/gateway/ingest` endpoint into your egress proxy and you have live defence. Set `VG_SLACK_WEBHOOK` and every red finding ships to #security. That's the full path from nothing to a DPDP-audit-ready control plane in under a week.

---

## Anticipated pushback we **cannot** answer yet

Being honest so we don't faceplant:

- **"Do you have real production customers?"** No — this is a hackathon build. The backend is battle-tested (**31/31 pytest passing**, deterministic, no flakes, including the `/selftest` rule-engine harness that verifies all 4 benchmark DPAs match expected verdicts on every boot) but we have no paying customers yet. We framed this as an MVP control plane with a clear hand-off to a pilot design-partner program.
- **"Do you have a fine-tuned LLM for DPDP?"** No — we deliberately don't fine-tune. Fine-tuning on legal text is a compliance liability (hallucination risk). We use TF-IDF retrieval over a verified corpus and a *labelled-optional* LLM polish for tone.
- **"Is your IsolationForest adversarially robust?"** Not meaningfully — it's trained on synthetic baselines. An adversary who knows the model can evade it. That's why we ship it alongside deterministic rules (rate limits, block-list, canary-access trigger), not as the only line of defence.

Honest framing beats cross-exam every time.

---

## Final "why us, why now" closer (15 seconds)

> India has 60M+ businesses, a new data-protection regime, and no SME-grade vendor control plane. OneTrust is built for Fortune 500 + GDPR. VendorGuard is built for the Indian CISO who just got a DPDP audit letter and has 30 days to respond. Rule-based where rules matter. ML where anomalies live. Evidence-grounded end-to-end. That's why we win.

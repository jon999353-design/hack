# VendorGuard AI — Competitive Landscape

Hackathon-honest positioning: **where we win, where the incumbents beat us, and why the India-SME segment is underserved.**

---

## TL;DR

| Capability | **VendorGuard AI v3.1** | OneTrust | Securiti.ai | BigID | Tsaaro / local consultancies |
|---|---|---|---|---|---|
| DPDP Act 2023 §-level coverage | ✅ 20 clauses, verbatim | ⚠️ GDPR-first, DPDP module add-on | ⚠️ DPDP module | ⚠️ DPDP module | ✅ (consulting deliverable) |
| DPDP Rules 2025 (R.1-R.22) | ✅ indexed in RAG | 🟡 partial | 🟡 partial | 🟡 partial | ⚠️ manual |
| ₹ penalty quantification per clause | ✅ per-rule, per-instance | ❌ | ❌ | ❌ | ⚠️ manual |
| Rule-based contract analysis with evidence trace | ✅ 17 rules, keyword+offset+snippet+confidence | ⚠️ LLM, opaque | ⚠️ LLM | ⚠️ LLM | ❌ |
| Gazette-page RAG citation | ✅ 49 passages | ❌ | ❌ | ❌ | ⚠️ PDF appendix |
| Live OSINT (crt.sh / DNS / TLS) | ✅ free, no keys | ❌ | ❌ | ❌ | ❌ |
| Sub-second behavioural gateway (IsolationForest + rules) | ✅ <100ms containment | ❌ (partner integrations) | ❌ | ❌ | ❌ |
| Canary tokens (tripwire) | ✅ minted in <200ms | 🟡 via partner | 🟡 | 🟡 | ❌ |
| Framework crosswalk (ISO / SOC 2 / NIST CSF) | ✅ auto, per-clause | ✅ | ✅ | ✅ | ⚠️ manual |
| Bulk vendor onboarding (25 parallel) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Monday-ready remediation playbook | ✅ owner / SLA / ₹ savings | 🟡 tasks module | 🟡 | 🟡 | ✅ |
| CERT-In 6-hour incident PDF | ✅ `/incident/{alert_id}.pdf` | ❌ | ❌ | ❌ | ⚠️ manual |
| Compliance Diff between scans | ✅ `/scan/{v}/diff` | 🟡 audit log | 🟡 | 🟡 | ❌ |
| Self-hostable / open core | ✅ | ❌ SaaS only | ❌ | ❌ | ❌ (consulting) |
| Typical annual cost (SME, ~200 vendors) | target: low $K or self-host | **~$50-80K** | ~$40-60K | ~$60-80K | ~$15-40K one-time |
| Time-to-first-value | **<2 min** (paste domain, get score) | weeks | weeks | weeks | weeks to months |

*Numbers for incumbents are public-website-listed starting prices or common-knowledge enterprise quotes. Exact ACV varies by seats / data sources / region. We are **not** claiming feature-parity with a $50K OneTrust SKU — we are claiming **fit-for-purpose** at the India SME-MSME tier they don't reach.*

---

## Where we win

### 1. **DPDP-native instead of DPDP-retrofitted**

OneTrust, Securiti and BigID were all architected for GDPR + CCPA. Their DPDP modules are translations — clause dictionaries bolted onto a GDPR ontology. That shows up in three ways:
- Their ₹ penalty math is an afterthought (they'll quote "up to ₹250 Cr" as a banner; we compute the max combined exposure per-clause).
- Their RAG (where they have one) doesn't cite gazette pages for the DPDP Act.
- They don't surface the India-specific Significant Data Fiduciary (§10) uplift as a first-class rule.

We built the taxonomy DPDP-first. That's not a feature; it's a ground-up data model.

### 2. **Evidence trace vs "AI said so"**

Every Contract Intel verdict in VendorGuard ships with:
- A **confidence score** (0.55 to 0.99) that scales with evidence + red-flag hits.
- An **evidence_trace** array — `{keyword, offset, snippet}` per positive match.
- A **red_flags_trace** array — same for negative patterns.
- A **verbatim Act quote** with gazette page.
- A **recommended rewrite** ready to counter-sign.

The LLM-first vendors (OneTrust's "AI assistant," Securiti's Copilot) will tell you a clause is risky but won't show you the substrings they matched on. That's a liability in a DPDP audit. Auditors want **citations**. We're built for that.

### 3. **Live defense is actually in the product**

VendorGuard's Live Defense panel is not a dashboard of integrations — it's an actual gateway endpoint (`POST /gateway/ingest`) running an IsolationForest + deterministic rule engine. Sub-100ms containment in the demo. That's a category none of the compliance-suite vendors play in (they integrate with a SIEM; they don't ship the gateway).

### 4. **Open core, self-hostable, SME-priced**

OneTrust / Securiti / BigID are SaaS multi-tenant with 6-figure ACVs. For a Bangalore SME with 200 vendors, that's non-consumable. VendorGuard is a FastAPI + static frontend — deployable on a $10/mo VPS. That's the moat at the bottom of the market.

### 5. **Reproducible benchmark**

The **Benchmark Evidence Ledger** (`/benchmark/dpas`) is three hand-written sample DPAs with baked-in expected verdicts — strong / ambiguous / weak. Judges (and auditors) can re-run them and verify the rule engine matches its claims. None of the incumbents expose an equivalent reproducibility harness.

---

## Where we lose (honest)

### 1. **Production scale & references**

OneTrust has tens of thousands of customers, SOC 2 Type II, ISO 27701, audit logs, SSO, RBAC, multi-tenancy, regional hosting, enterprise SLAs. We have a hackathon MVP. For a 10,000-vendor Fortune 500 in India (e.g. a TCS or Reliance), they'll still go OneTrust. Our target is the **next 100,000 SMEs**, not the top 100.

### 2. **Breadth of integrations**

OneTrust ships 200+ data connectors. We ship crt.sh, DNS, TLS, plus key-gated Shodan / HIBP / VirusTotal / nuclei. For a GDPR + DPDP + CCPA + LGPD multi-regime enterprise, we're not the answer yet.

### 3. **GRC workflow depth**

OneTrust has decades of workflow engine — approvals, policy lifecycle, attestations, quarterly access reviews, DSR portal. We have a Monday Playbook PDF. For a regulated-industry CISO, that gap matters.

### 4. **Legal liability posture**

OneTrust carries E&O insurance and indemnification. We're a hackathon build. A design-partner pilot would have to come with a carefully scoped commercial agreement.

---

## Why this is a real India SME moat — not just "cheaper"

India's digital-economy pyramid is inverted from the US / EU:

- ~1,000 enterprises who will buy a $50-80K compliance SKU.
- ~60 **million** registered businesses.
- ~7 million MSMEs with formal IT spend.

DPDP Act 2023 applies to all of them. The Data Protection Board can issue penalties up to **₹250 crore per contravention**. The DPDP Rules 2025 expand the obligations (Rule 6 log retention, Rule 12 SDF audits, cross-border Schedule). There is **no** SME-priced, DPDP-native, evidence-grounded vendor control plane in the market today. The incumbents are priced out of the segment by their own architecture (multi-tenant SaaS with heavy sales motion).

VendorGuard is the SME-tier answer, and the evidence-trace + live-gateway architecture means we're not "OneTrust Lite" — we solve a different problem (real-time vendor access control) at a different price point.

---

## Why we'd win the hackathon specifically

Judges at Athernex 2026 are optimising for a blend of:
1. **Technical depth** — we ship real OSINT, real ML, real rules, with a reproducible benchmark and 27-test CI. We're not LLM glue.
2. **India relevance** — DPDP-first, ₹ penalty math, CERT-In 6-hour incident PDF, §10 SDF uplift. Nothing bolted-on.
3. **Demo-ability** — one sidebar, five panels, 90-second pitch arc. Sub-100ms gateway, sub-1s contract analysis, sub-2s bulk scan, all visible on one screen.
4. **Honesty** — we label what's rules, what's ML, what's LLM, and what's seeded when no API key is set. No "AI-washing."

That combination is rare. Most hackathon entries are either pure-LLM (shallow) or pure-heuristic (no novelty). VendorGuard is the deliberate third thing: **rules where rules belong, ML where ML belongs, LLM where it adds polish.** That's the message we take to the judges.

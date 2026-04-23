"""Contract Intelligence (Layer 5) — DPA / MSA gap analysis.

Parses a vendor Data Processing Agreement (or any contract text) and scores
each DPDP Act obligation as:

- green  → clause is covered by text in the contract
- amber  → clause is missing (no evidence, no red flag)
- red    → clause is present AND explicitly violated (e.g. "US data centers"
           against §16 data-localisation, "no audit rights" against §8(4))

Each gap carries: the obligation, the ₹ max penalty, verbatim Act quote,
suggested rewrite, and the ISO 27001 / SOC 2 / NIST CSF crosswalk.

No LLM required — evidence/red-flag matching is deterministic so the demo
works offline. `polish_rewrite()` is an optional async helper that can
LLM-rewrite a single recommended clause if an AI provider is configured.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.config import settings
from app.modules.framework import crosswalk_for
from app.modules.rag import retriever

_CATALOG = json.loads(
    (Path(__file__).parent.parent / "data" / "dpdp_clauses.json").read_text()
)
_CLAUSES_BY_SECTION: dict[str, dict[str, Any]] = {
    c["section"]: c for c in _CATALOG["clauses"]
}


# Order matters — judges read top-down. Keep the biggest-penalty / most-
# frequently-missed obligations near the top.
_RULES: list[dict[str, Any]] = [
    {
        "section": "§8(5)",
        "label": "Reasonable security safeguards",
        "evidence_keywords": [
            "reasonable security", "security safeguard", "encryption at rest",
            "encryption in transit", "tls", "mfa", "multi-factor",
            "access control", "least privilege",
        ],
        "red_flags": [
            r"best[- ]effort[s]? to secure",
            r"as[- ]is",
            r"no warranty of security",
        ],
        "rewrite": (
            "Processor shall implement and maintain appropriate technical and "
            "organisational measures to ensure a level of security appropriate "
            "to the risk, including encryption of Personal Data at rest and in "
            "transit (TLS 1.2+), multi-factor authentication for privileged "
            "access, least-privilege IAM, and continuous vulnerability "
            "management, in accordance with §8(5) of the DPDP Act, 2023."
        ),
    },
    {
        "section": "§8(6)",
        "label": "Breach notification within 72 hours",
        "evidence_keywords": [
            "notify controller", "notify within", "breach notification",
            "24 hours", "48 hours", "72 hours", "data protection board",
        ],
        "red_flags": [
            r"as soon as practicable",
            r"reasonable time",
            r"without undue delay(?!.*\d)",
        ],
        "missing_is_red": True,  # no breach-notification clause = outright §8(6) violation
        "rewrite": (
            "Processor shall notify Controller in writing without undue delay "
            "and in no event later than twenty-four (24) hours of becoming "
            "aware of any Personal Data breach, providing all information "
            "reasonably required for Controller to meet its obligations under "
            "§8(6) of the DPDP Act, 2023 (notification to the Data Protection "
            "Board and affected Data Principals)."
        ),
    },
    {
        "section": "§8(4)",
        "label": "Written DPA with purpose limitation",
        "evidence_keywords": [
            "purpose limitation", "only for the purposes", "sub-processor",
            "subprocessor", "data processor", "written contract",
        ],
        "red_flags": [
            r"vendor may use (data|personal data) for any purpose",
            r"no restriction on use",
        ],
        "rewrite": (
            "Processor shall Process Personal Data only for the documented "
            "purposes of the Services and only on documented instructions of "
            "Controller, shall not engage any sub-processor without Controller's "
            "prior written authorisation, and shall flow down equivalent "
            "obligations to each sub-processor, as required under §8(4) of "
            "the DPDP Act, 2023."
        ),
    },
    {
        "section": "§16",
        "label": "Cross-border transfer restriction",
        "evidence_keywords": [
            "data will reside in india", "data shall reside in india",
            "personal data shall reside in india", "india region",
            "in-country", "data localisation", "data localization",
            "only in india",
        ],
        "red_flags": [
            r"united states data center",
            r"us data center",
            r"stored in (the )?us(a|\b)",
            r"stored outside india",
            r"any jurisdiction",
        ],
        "rewrite": (
            "Processor shall store and Process Personal Data solely within "
            "India, and shall not transfer Personal Data outside India except "
            "to jurisdictions notified by the Central Government under §16 of "
            "the DPDP Act, 2023, and in any event only under Controller's "
            "prior written instructions."
        ),
    },
    {
        "section": "§8(7)",
        "label": "Retention and erasure on purpose end",
        "evidence_keywords": [
            "data will be deleted", "data shall be deleted", "data will be erased",
            "upon termination", "retention period", "retention limited",
            "retain personal data", "purge", "erase",
        ],
        "red_flags": [
            r"retain[s]? data indefinitely",
            r"no deletion",
            r"no obligation to delete",
        ],
        "rewrite": (
            "Processor shall retain Personal Data only for as long as is "
            "necessary for the documented purposes and, upon expiry of such "
            "purpose or on termination of the Services, shall delete or return "
            "all Personal Data (and any copies) within thirty (30) days and "
            "certify such deletion in writing, per §8(7) of the DPDP Act, 2023."
        ),
    },
    {
        "section": "§11",
        "label": "Data Principal rights (access / correction / erasure)",
        "evidence_keywords": [
            "data principal rights", "data subject rights", "right to access",
            "right to correction", "right to erasure", "right to rectification",
            "dsr", "within 14 days", "respond to data subject",
        ],
        "red_flags": [
            r"at additional cost to controller",
            r"controller fee",
            r"not support data subject",
            r"no right of access",
        ],
        "rewrite": (
            "Processor shall, at no additional cost, assist Controller by "
            "appropriate technical and organisational measures in responding "
            "to requests from Data Principals exercising their rights under "
            "Chapter III of the DPDP Act, 2023 (access, correction, completion, "
            "updating, and erasure), within fourteen (14) days of Controller's "
            "request."
        ),
    },
    {
        "section": "§8(8)",
        "label": "Grievance redressal mechanism",
        "evidence_keywords": [
            "grievance officer", "grievance redressal", "grievance mechanism",
            "complaint",
        ],
        "red_flags": [
            r"no grievance",
        ],
        "rewrite": (
            "Processor shall publish and maintain a grievance-redressal "
            "mechanism, name and contact details of a designated grievance "
            "officer, and respond to complaints of Data Principals within "
            "seven (7) working days, in accordance with §8(8) of the DPDP "
            "Act, 2023."
        ),
    },
    {
        "section": "§10",
        "label": "Data Protection Officer / DPIA",
        "evidence_keywords": [
            "data protection officer", "dpo", "dpia",
            "data protection impact assessment",
        ],
        "red_flags": [],
        "rewrite": (
            "Where Controller is classified as a Significant Data Fiduciary, "
            "Processor shall cooperate with Controller's Data Protection "
            "Officer and contribute to any Data Protection Impact Assessment "
            "(DPIA) required under §10 of the DPDP Act, 2023."
        ),
    },
    {
        "section": "§6",
        "label": "Consent capture and withdrawal",
        "evidence_keywords": [
            "consent of the data principal", "consent of data principal",
            "lawful basis", "withdraw consent", "consent withdrawal",
            "free, specific, informed",
        ],
        "red_flags": [
            r"consent is deemed",
            r"opt-out only",
        ],
        "rewrite": (
            "Processor shall only Process Personal Data where Controller has "
            "obtained free, specific, informed, unconditional and unambiguous "
            "consent from the Data Principal (or where a Legitimate Use under "
            "§7 applies) and shall cease Processing promptly on withdrawal of "
            "such consent, in accordance with §6 of the DPDP Act, 2023."
        ),
    },
    {
        "section": "§5",
        "label": "Notice to Data Principal",
        "evidence_keywords": [
            "privacy notice", "plain language", "notice to data principal",
            "notice in english",
        ],
        "red_flags": [],
        "rewrite": (
            "Processor shall support Controller in providing a clear, plain-"
            "language privacy notice to Data Principals describing the "
            "Personal Data Processed, the purpose of Processing, and the "
            "rights of Data Principals, in English and the scheduled languages "
            "required under §5 of the DPDP Act, 2023."
        ),
    },
    {
        "section": "§8(4)-audit",
        "label": "Audit rights for Controller",
        "evidence_keywords": [
            "audit right", "right to audit", "grants audit", "audit by controller",
        ],
        "red_flags": [
            r"no audit right",
            r"audit rights are not granted",
        ],
        "rewrite": (
            "Processor shall make available to Controller all information "
            "necessary to demonstrate compliance with this Addendum and allow "
            "for and contribute to audits, including inspections, conducted "
            "by Controller or an auditor mandated by Controller, on reasonable "
            "notice, in accordance with §8(4) of the DPDP Act, 2023."
        ),
    },
]


def _find_evidence(text: str, keywords: list[str]) -> list[str]:
    out: list[str] = []
    low = text.lower()
    for kw in keywords:
        idx = low.find(kw.lower())
        if idx >= 0:
            start = max(0, idx - 30)
            end = min(len(text), idx + len(kw) + 40)
            out.append(text[start:end].strip().replace("\n", " "))
            if len(out) >= 2:
                break
    return out


def _find_red_flags(text: str, patterns: list[str]) -> list[str]:
    out: list[str] = []
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            idx = m.start()
            start = max(0, idx - 30)
            end = min(len(text), m.end() + 40)
            out.append(text[start:end].strip().replace("\n", " "))
            if len(out) >= 2:
                break
    return out


def _status_for(evidence: list[str], red_flags: list[str], missing_is_red: bool = False) -> str:
    if red_flags:
        return "red"
    if evidence:
        return "green"
    return "red" if missing_is_red else "amber"


def _penalty_for(section: str) -> int:
    # §8(4)-audit is a virtual sub-row under §8(4); use §8(4) penalty.
    base = section.split("-")[0]
    c = _CLAUSES_BY_SECTION.get(base)
    return int(c["max_penalty_inr"]) if c else 0


def _obligation_for(section: str) -> str:
    base = section.split("-")[0]
    c = _CLAUSES_BY_SECTION.get(base)
    return c["obligation"] if c else ""


def analyze(text: str) -> dict[str, Any]:
    """Run the DPDP gap analysis over a contract text."""
    text = text or ""
    r = retriever()
    gaps: list[dict[str, Any]] = []
    for rule in _RULES:
        section = rule["section"]
        evidence = _find_evidence(text, rule["evidence_keywords"])
        red_flags = _find_red_flags(text, rule["red_flags"])
        status = _status_for(evidence, red_flags, bool(rule.get("missing_is_red")))

        base_section = section.split("-")[0]
        hit = r.lookup_clause(base_section)
        rag_quote = hit["excerpt"] if hit else None
        rag_citation = (
            f"DPDP Act 2023, {base_section}, Gazette p. {hit['page']}"
            if hit and hit.get("page") else (f"DPDP Act 2023, {base_section}" if hit else None)
        )

        gaps.append({
            "section": base_section,
            "rule_id": section,
            "label": rule["label"],
            "status": status,
            "obligation": _obligation_for(section),
            "penalty_inr": _penalty_for(section),
            "evidence": evidence,
            "red_flags": red_flags,
            "rag_quote": rag_quote,
            "rag_citation": rag_citation,
            "recommended_rewrite": rule["rewrite"],
            "crosswalk": crosswalk_for(base_section),
        })

    red_count = sum(1 for g in gaps if g["status"] == "red")
    amber_count = sum(1 for g in gaps if g["status"] == "amber")
    green_count = sum(1 for g in gaps if g["status"] == "green")
    total = max(len(gaps), 1)
    # Coverage weights green=1, amber=0, red=0 (explicit violation is strictly worse than missing).
    coverage_pct = int(round((green_count / total) * 100))

    # Potential penalty = max penalty per distinct DPDP section that is red OR amber.
    by_section: dict[str, int] = {}
    for g in gaps:
        if g["status"] == "green":
            continue
        sec = g["section"]
        by_section[sec] = max(by_section.get(sec, 0), int(g["penalty_inr"] or 0))
    potential_penalty = int(sum(by_section.values()))

    summary = _summarise(red_count, amber_count, green_count, potential_penalty)

    return {
        "coverage_pct": coverage_pct,
        "red_count": red_count,
        "amber_count": amber_count,
        "green_count": green_count,
        "total_clauses_checked": len(gaps),
        "potential_penalty_inr": potential_penalty,
        "summary": summary,
        "gaps": gaps,
    }


def _summarise(red: int, amber: int, green: int, penalty: int) -> str:
    cr = f"₹{penalty / 1e7:.1f} Cr" if penalty >= 1e7 else f"₹{penalty:,}"
    if red + amber == 0:
        return (
            f"Strong DPA. {green} DPDP obligations are explicitly covered. "
            "No red or amber findings — safe to counter-sign after legal review."
        )
    bits = []
    if red:
        bits.append(f"{red} red clause{'s' if red != 1 else ''} (explicit violation)")
    if amber:
        bits.append(f"{amber} amber clause{'s' if amber != 1 else ''} (missing obligation)")
    bits.append(f"{green} green clause{'s' if green != 1 else ''} covered")
    head = ", ".join(bits)
    return (
        f"{head}. If signed as-is, maximum combined DPDP exposure is {cr}. "
        "Request rewrites on the red and amber rows before counter-signature."
    )


async def polish_rewrite(label: str, rewrite: str) -> str:
    """Optional: ask the configured LLM to polish a recommended rewrite.

    Returns the original rewrite on any error so the demo path is never broken.
    """
    if not settings.has_ai:
        return rewrite
    prompt = (
        "You are an Indian data-protection lawyer. Polish the following "
        f"suggested contract clause for the obligation '{label}'. Keep it "
        "legally precise, reference the DPDP Act, 2023, and return ONLY the "
        "revised clause (no preamble).\n\n"
        f"Draft:\n{rewrite}"
    )
    try:
        if settings.ai_provider == "anthropic":
            from anthropic import AsyncAnthropic

            client = AsyncAnthropic(api_key=settings.anthropic_api_key)
            msg = await client.messages.create(
                model=settings.anthropic_model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            parts = [p.text for p in msg.content if getattr(p, "type", "") == "text"]
            return "\n".join(parts).strip() or rewrite
        if settings.ai_provider in ("openai", "openrouter"):
            from openai import AsyncOpenAI

            base_url = (
                settings.openrouter_base_url
                if settings.ai_provider == "openrouter"
                else (settings.openai_base_url or None)
            )
            key = (
                settings.openrouter_api_key
                if settings.ai_provider == "openrouter"
                else settings.openai_api_key
            )
            model = (
                settings.openrouter_model
                if settings.ai_provider == "openrouter"
                else settings.openai_model
            )
            client = AsyncOpenAI(api_key=key, base_url=base_url)
            r = await client.chat.completions.create(
                model=model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            return (r.choices[0].message.content or rewrite).strip()
    except Exception:
        return rewrite
    return rewrite

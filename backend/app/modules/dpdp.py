"""DPDP Compliance Mapper.

Takes raw OSINT findings and maps each to a Digital Personal Data Protection
Act, 2023 clause + obligation + max penalty + remediation step. Each mapping
is enriched with a verbatim Act excerpt from the RAG retriever so the UI /
PDF report can show judges the exact gazette quote.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.modules.framework import crosswalk_for
from app.modules.rag import retriever
from app.schemas import DPDPMapping, Finding

DATA = Path(__file__).parent.parent / "data" / "dpdp_clauses.json"
_CATALOG = json.loads(DATA.read_text())
_CLAUSES = {c["id"]: c for c in _CATALOG["clauses"]}
_MAP = _CATALOG["finding_to_clause"]


def _tag_for(f: Finding) -> str:
    ev_tag = None
    if isinstance(f.evidence, dict):
        ev_tag = f.evidence.get("tag")
    if ev_tag and ev_tag in _MAP:
        return ev_tag
    # Source-based fallback
    s = f.source.lower()
    if s == "hibp":
        return "leaked_credentials"
    if s == "shodan":
        return "open_database_port"
    if s in ("tls", "dns"):
        return "weak_tls"
    if s == "virustotal":
        return "breach_history"
    if s == "crt.sh":
        return "exposed_pii_endpoint"
    if s == "nuclei":
        return "cve_exposure"
    return "open_database_port"


def map_findings(findings: list[Finding]) -> list[DPDPMapping]:
    out: list[DPDPMapping] = []
    r = retriever()
    for f in findings:
        tag = _tag_for(f)
        clause_id = _MAP.get(tag)
        if not clause_id:
            continue
        c = _CLAUSES[clause_id]
        quote = None
        citation = None
        hit = r.lookup_clause(c["section"])
        if hit:
            quote = hit["excerpt"]
            citation = f"DPDP Act 2023, {c['section']}, Gazette p. {hit['page']}" if hit.get("page") else f"DPDP Act 2023, {c['section']}"
        out.append(
            DPDPMapping(
                finding_id=f.id,
                clause=c["section"],
                obligation=c["obligation"],
                max_penalty_inr=c["max_penalty_inr"],
                immediate_action=c["immediate_action"],
                liability_note=c["liability_note"],
                rag_quote=quote,
                rag_citation=citation,
                crosswalk=crosswalk_for(c["section"]),
            )
        )
    return out


def total_exposure(mappings: list[DPDPMapping]) -> int:
    """Exposure = sum of max penalties per *distinct* clause (DPB cannot
    double-count the same clause in most scenarios)."""
    by_clause: dict[str, int] = {}
    for m in mappings:
        by_clause[m.clause] = max(by_clause.get(m.clause, 0), m.max_penalty_inr)
    return sum(by_clause.values())


def format_inr(amount: int) -> str:
    """Return Indian-style short form: 2500000000 → '₹250 Cr'."""
    if amount >= 10_000_000:
        return f"₹{amount / 10_000_000:.0f} Cr"
    if amount >= 100_000:
        return f"₹{amount / 100_000:.0f} L"
    return f"₹{amount:,}"

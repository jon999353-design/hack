"""Remediation Playbook generator.

Turns a vendor scan into an ordered Monday-morning checklist:
each task is tied to a DPDP clause, has an owner (CISO / DPO / SRE / Legal),
an SLA, an estimated ₹ penalty-exposure avoided by completing it, and the
verbatim DPDP quote for justification in writing.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.modules.framework import crosswalk_for
from app.modules.rag import retriever

_CATALOG = json.loads(
    (Path(__file__).parent.parent / "data" / "dpdp_clauses.json").read_text()
)
_CLAUSES_BY_SECTION = {c["section"]: c for c in _CATALOG["clauses"]}

# Per-DPDP-clause default playbook entry. Owners are chosen to mirror how a
# typical Indian mid-market CISO team assigns this work.
_ENTRIES = {
    "§8(5)": {
        "owner": "SRE + Security Eng",
        "task": "Rotate vendor credentials; patch exposed CVEs; enforce TLS 1.2+; enable MFA.",
        "sla_days": 14,
    },
    "§8(4)": {
        "owner": "Legal + Procurement",
        "task": "Amend DPA to add purpose-limitation and sub-processor clauses; counter-sign.",
        "sla_days": 30,
    },
    "§8(6)": {
        "owner": "Security + DPO",
        "task": "Stand up 24h breach-notification runbook; rehearse DPB + Data Principal comms.",
        "sla_days": 7,
    },
    "§8(7)": {
        "owner": "Data Engineering + DPO",
        "task": "Audit retention; delete records past purpose; add automated erasure pipeline.",
        "sla_days": 21,
    },
    "§8(8)": {
        "owner": "DPO",
        "task": "Publish grievance officer email + response SLA of 7 working days.",
        "sla_days": 5,
    },
    "§16": {
        "owner": "Cloud + Legal",
        "task": "Repatriate data to India region OR confirm vendor jurisdiction is DPB-notified.",
        "sla_days": 30,
    },
    "§11": {
        "owner": "Product + DPO",
        "task": "Build DSR (access/correction/erasure) workflow with <14d SLA.",
        "sla_days": 30,
    },
    "§9": {
        "owner": "Product + DPO",
        "task": "Add age-verification + verifiable-parental-consent gate; remove targeted ads.",
        "sla_days": 30,
    },
    "§10": {
        "owner": "CISO",
        "task": "Appoint DPO; commission DPIA if classified as Significant Data Fiduciary.",
        "sla_days": 45,
    },
    "§5": {
        "owner": "Product + Legal",
        "task": "Publish plain-language privacy notice in English + scheduled languages.",
        "sla_days": 21,
    },
    "§6": {
        "owner": "Product + DPO",
        "task": "Implement consent capture + withdrawal flow for every processing purpose.",
        "sla_days": 21,
    },
    "§4": {
        "owner": "DPO",
        "task": "Document lawful basis per processing activity; update RoPA.",
        "sla_days": 14,
    },
}


def build_for(scan: dict[str, Any]) -> dict[str, Any]:
    """Build a playbook from a stored /scan/{vendor} result."""
    vendor = scan.get("vendor", "")
    mappings = scan.get("dpdp", []) or []
    findings = {f["id"]: f for f in (scan.get("findings") or [])}

    # Group by clause, compute total penalty avoidable per clause.
    by_clause: dict[str, dict[str, Any]] = {}
    for m in mappings:
        clause = m.get("clause")
        if not clause:
            continue
        cur = by_clause.get(clause)
        if cur is None:
            cur = {
                "clause": clause,
                "obligation": m.get("obligation"),
                "penalty_inr": int(m.get("max_penalty_inr") or 0),
                "rag_quote": m.get("rag_quote"),
                "rag_citation": m.get("rag_citation"),
                "triggering_findings": [],
            }
            by_clause[clause] = cur
        else:
            # Penalty per distinct clause is fixed — take the max.
            cur["penalty_inr"] = max(cur["penalty_inr"], int(m.get("max_penalty_inr") or 0))
        fid = m.get("finding_id")
        if fid and fid in findings:
            cur["triggering_findings"].append({
                "id": fid,
                "source": findings[fid].get("source"),
                "severity": findings[fid].get("severity"),
                "title": findings[fid].get("title"),
            })

    r = retriever()
    rows: list[dict[str, Any]] = []
    for clause, bundle in by_clause.items():
        entry = _ENTRIES.get(clause, {
            "owner": "Security",
            "task": f"Remediate {clause} obligation; evidence for DPB audit file.",
            "sla_days": 30,
        })
        if not bundle.get("rag_quote"):
            hit = r.lookup_clause(clause)
            if hit:
                bundle["rag_quote"] = hit["excerpt"]
                bundle["rag_citation"] = (
                    f"DPDP Act 2023, {clause}, Gazette p. {hit['page']}"
                    if hit.get("page") else f"DPDP Act 2023, {clause}"
                )
        rows.append({
            "clause": clause,
            "title": _CLAUSES_BY_SECTION.get(clause, {}).get("title", ""),
            "obligation": bundle["obligation"],
            "task": entry["task"],
            "owner": entry["owner"],
            "sla_days": entry["sla_days"],
            "penalty_inr_if_unaddressed": bundle["penalty_inr"],
            "savings_inr_if_addressed": bundle["penalty_inr"],
            "triggering_findings": bundle["triggering_findings"],
            "rag_quote": bundle["rag_quote"],
            "rag_citation": bundle["rag_citation"],
            "crosswalk": crosswalk_for(clause),
        })

    # Sort by biggest ₹ impact first.
    rows.sort(key=lambda r: (-r["penalty_inr_if_unaddressed"], r["sla_days"]))
    total_savings = sum(r["savings_inr_if_addressed"] for r in rows)

    return {
        "vendor": vendor,
        "items": rows,
        "total_items": len(rows),
        "total_savings_inr": total_savings,
        "next_7_days": [r for r in rows if r["sla_days"] <= 7],
        "next_30_days": [r for r in rows if 7 < r["sla_days"] <= 30],
        "long_horizon": [r for r in rows if r["sla_days"] > 30],
    }

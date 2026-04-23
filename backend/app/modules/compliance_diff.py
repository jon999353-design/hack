"""Compliance Diff — compare two scans for the same vendor.

Answers the question a judge (and every CISO) asks after the first scan:
"what changed?" Takes two scan snapshots and produces a deterministic diff:

- trust score delta (integer points)
- exposure delta (₹)
- new findings (present in B, not in A) with severity + DPDP clause
- resolved findings (present in A, not in B)
- unchanged findings (present in both) — capped to keep payload sane
- clause coverage delta (which DPDP clauses newly appear / drop)

No ML, no LLM — pure set-arithmetic over `finding.id` so the output is
fully auditable.
"""
from __future__ import annotations

from typing import Any


def _index(scan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["id"]: f for f in (scan.get("findings") or [])}


def _clauses(scan: dict[str, Any]) -> set[str]:
    return {m["clause"] for m in (scan.get("dpdp") or []) if m.get("clause")}


def diff(old: dict[str, Any] | None, new: dict[str, Any] | None) -> dict[str, Any]:
    """Return a structured diff. Either side may be None (first-ever scan)."""
    if new is None:
        return {
            "error": "No current scan to diff against.",
        }
    new_idx = _index(new)
    new_score = int((new.get("trust") or {}).get("score") or 0)
    new_exposure = int(new.get("total_dpdp_exposure_inr") or 0)
    new_clauses = _clauses(new)

    if old is None:
        return {
            "from": None,
            "to": {
                "scanned_at": new.get("scanned_at"),
                "score": new_score,
                "exposure_inr": new_exposure,
            },
            "score_delta": None,
            "exposure_delta_inr": None,
            "new_findings": list(new_idx.values()),
            "resolved_findings": [],
            "unchanged_findings": [],
            "new_clauses": sorted(new_clauses),
            "resolved_clauses": [],
            "summary": (
                "First scan for this vendor. "
                f"Trust score {new_score}/100, exposure ₹{new_exposure / 1e7:.1f} Cr, "
                f"{len(new_idx)} findings, {len(new_clauses)} DPDP clauses triggered."
            ),
        }

    old_idx = _index(old)
    old_score = int((old.get("trust") or {}).get("score") or 0)
    old_exposure = int(old.get("total_dpdp_exposure_inr") or 0)
    old_clauses = _clauses(old)

    added_ids = set(new_idx) - set(old_idx)
    removed_ids = set(old_idx) - set(new_idx)
    same_ids = set(new_idx) & set(old_idx)

    added = [new_idx[i] for i in sorted(added_ids)]
    removed = [old_idx[i] for i in sorted(removed_ids)]
    unchanged = [new_idx[i] for i in sorted(same_ids)][:10]

    score_delta = new_score - old_score
    exposure_delta = new_exposure - old_exposure
    new_clauses_set = new_clauses - old_clauses
    resolved_clauses_set = old_clauses - new_clauses

    verb = "improved" if score_delta > 0 else ("worsened" if score_delta < 0 else "unchanged")
    exp_cr_delta = exposure_delta / 1e7
    exp_direction = "reduced" if exp_cr_delta < 0 else ("increased" if exp_cr_delta > 0 else "unchanged")
    summary_bits = [
        f"Trust score {verb} by {abs(score_delta)} point{'s' if abs(score_delta) != 1 else ''}.",
        (
            f"Exposure {exp_direction} by ₹{abs(exp_cr_delta):.2f} Cr."
            if exposure_delta != 0 else "Exposure unchanged."
        ),
    ]
    if added:
        summary_bits.append(f"{len(added)} new finding{'s' if len(added) != 1 else ''}.")
    if removed:
        summary_bits.append(f"{len(removed)} finding{'s' if len(removed) != 1 else ''} resolved.")
    if new_clauses_set:
        summary_bits.append(f"New DPDP clause exposure: {', '.join(sorted(new_clauses_set))}.")
    if resolved_clauses_set:
        summary_bits.append(f"Cleared DPDP clauses: {', '.join(sorted(resolved_clauses_set))}.")

    return {
        "from": {
            "scanned_at": old.get("scanned_at"),
            "score": old_score,
            "exposure_inr": old_exposure,
        },
        "to": {
            "scanned_at": new.get("scanned_at"),
            "score": new_score,
            "exposure_inr": new_exposure,
        },
        "score_delta": score_delta,
        "exposure_delta_inr": exposure_delta,
        "new_findings": added,
        "resolved_findings": removed,
        "unchanged_findings": unchanged,
        "new_clauses": sorted(new_clauses_set),
        "resolved_clauses": sorted(resolved_clauses_set),
        "summary": " ".join(summary_bits),
    }

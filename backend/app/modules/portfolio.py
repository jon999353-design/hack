"""Executive Board / Portfolio KPIs.

Aggregates everything we know across all vendors into one CISO-facing view:
- total ₹ DPDP exposure under watch
- total ₹ saved / avoided from gateway blocks
- attacks auto-contained count
- vendors by band (safe / watch / block)
- top 3 DPDP clauses triggered across portfolio
- framework crosswalk counters (ISO 27001 / SOC 2 / NIST CSF controls touched)
- vendor leaderboard (worst → best)
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from app.modules import store
from app.modules.framework import crosswalk_for, frameworks_catalog


async def build() -> dict[str, Any]:
    vendors = await store.list_vendors()
    alerts = await store.recent_alerts(500)

    blocked_alerts = [a for a in alerts if a.get("severity") in ("critical", "high")]
    attacks_blocked = len(blocked_alerts)
    savings_inr = sum(int(a.get("dpdp_exposure_inr") or 0) for a in blocked_alerts)

    total_exposure = sum(int(v.get("exposure_inr") or 0) for v in vendors)
    avg_score = int(
        round(sum(int(v.get("score") or 0) for v in vendors) / max(len(vendors), 1))
    ) if vendors else 0

    bands = Counter((v.get("band") or "watch") for v in vendors)

    leaderboard = sorted(
        vendors,
        key=lambda v: (v.get("score") or 100),
    )[:10]

    # Pull per-vendor scans to compute DPDP clause hotspots + framework counts.
    clause_counter: Counter = Counter()
    iso_counter: Counter = Counter()
    soc_counter: Counter = Counter()
    nist_counter: Counter = Counter()
    for v in vendors:
        scan = await store.load_scan(v["vendor"])
        if not scan:
            continue
        for m in (scan.get("dpdp") or []):
            clause = m.get("clause")
            if not clause:
                continue
            clause_counter[clause] += 1
            cx = crosswalk_for(clause)
            for ctrl in cx.get("iso27001", []):
                iso_counter[ctrl] += 1
            for ctrl in cx.get("soc2", []):
                soc_counter[ctrl] += 1
            for ctrl in cx.get("nist_csf", []):
                nist_counter[ctrl] += 1

    return {
        "vendors_tracked": len(vendors),
        "avg_trust_score": avg_score,
        "total_exposure_inr": int(total_exposure),
        "attacks_blocked": attacks_blocked,
        "savings_inr": int(savings_inr),
        "bands": {
            "safe": int(bands.get("safe", 0)),
            "watch": int(bands.get("watch", 0)),
            "block": int(bands.get("block", 0)),
        },
        "top_clauses": [
            {"clause": c, "vendors_affected": n}
            for c, n in clause_counter.most_common(5)
        ],
        "framework_coverage": {
            "catalog": frameworks_catalog(),
            "iso27001_controls_triggered": iso_counter.most_common(10),
            "soc2_criteria_triggered": soc_counter.most_common(10),
            "nist_csf_functions_triggered": nist_counter.most_common(10),
        },
        "leaderboard": leaderboard,
        "recent_alerts": alerts[:10],
    }

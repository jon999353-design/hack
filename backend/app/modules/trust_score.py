"""Trust Score engine.

Bounded weighted-sum score (0–100) with per-source caps so no single
integration can dominate the score. Bands:

  ≥ 80  → Safe to onboard (green)
  50-79 → Onboard with remediation (amber)
  <  50 → Do not onboard (red)

This is intentionally *not* an ML model — the score needs to be explainable
so a CISO can justify each deduction in writing. The ML piece lives in
`anomaly.py` (gateway behavioural engine).
"""
from __future__ import annotations

from app.schemas import Finding, ScoreBand

SEVERITY_SCALE = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.2,
}

SOURCE_WEIGHTS = {
    "hibp": 25,
    "shodan": 20,
    "virustotal": 15,
    "tls": 10,
    "dns": 10,
    "crt.sh": 5,
    "nuclei": 20,
    "dpdp-rule": 15,
}

# Cap each source so one noisy tool can't zero out the score on its own.
SOURCE_MAX_DEDUCTION = {
    "hibp": 25,
    "shodan": 25,
    "virustotal": 15,
    "tls": 12,
    "dns": 8,
    "crt.sh": 8,
    "nuclei": 25,
    "dpdp-rule": 20,
}


def compute_score(findings: list[Finding]) -> ScoreBand:
    by_source: dict[str, float] = {}
    for f in findings:
        w = SOURCE_WEIGHTS.get(f.source, 5)
        s = SEVERITY_SCALE.get(f.severity, 0.3)
        by_source[f.source] = by_source.get(f.source, 0.0) + w * s

    deduction = 0.0
    for source, raw in by_source.items():
        cap = SOURCE_MAX_DEDUCTION.get(source, 10)
        deduction += min(raw, cap)

    raw = 100 - deduction
    score = max(0, min(100, int(round(raw))))

    if score >= 80:
        band, color, label = "safe", "#16a34a", "Safe to onboard"
    elif score >= 50:
        band, color, label = "watch", "#f59e0b", "Onboard with remediation"
    else:
        band, color, label = "block", "#dc2626", "Do not onboard"

    return ScoreBand(score=score, band=band, color=color, label=label)

"""End-to-end smoke tests. Run with: pytest -q from the backend/ directory."""
from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# Isolate each test run into its own SQLite file so tests are independent of
# whatever lives in the repo root.
os.environ["SQLITE_PATH"] = os.path.join(tempfile.gettempdir(), "vg_smoke.db")
if os.path.exists(os.environ["SQLITE_PATH"]):
    os.remove(os.environ["SQLITE_PATH"])

from app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "VendorGuard AI"
    assert body["version"].startswith(("2.", "3."))
    assert "behavioural_ml" in body["engines"]
    assert body["engines"]["behavioural_ml"]["model"] == "IsolationForest"


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_scan_demo_vendor(client):
    r = client.post("/scan", json={"vendor": "paytrust-partner.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["vendor"] == "paytrust-partner.com"
    assert len(body["findings"]) >= 5
    assert body["total_dpdp_exposure_inr"] > 0
    assert 0 <= body["trust"]["score"] <= 100
    # RAG enrichment on at least one mapping
    assert any(m.get("rag_quote") for m in body["dpdp"])


def test_gateway_flow_blocks_bulk_export(client):
    v = "paytrust-partner.com"
    # Reset from any prior test run
    client.post(f"/gateway/reset/{v}")
    r = client.post("/gateway/activate", json={
        "vendor": v, "scope": ["reporting"], "max_records_per_request": 500,
    })
    assert r.status_code == 200
    assert r.json()["active"] is True

    r = client.post("/gateway/proxy", json={
        "vendor": v, "endpoint": "reporting/export", "records_requested": 12000,
        "client_ip": "203.0.113.42",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "block"
    assert body["event"] is not None
    # Containment time is real wall-clock and must be < 5s
    assert 0.0 < body["event"]["containment_seconds"] < 5.0
    # Anomaly score should be surfaced
    assert body["event"]["anomaly_score"] is not None


def test_gateway_allows_normal_traffic(client):
    v = "paytrust-partner.com"
    client.post(f"/gateway/reset/{v}")
    r = client.post("/gateway/proxy", json={
        "vendor": v, "endpoint": "reporting/daily", "records_requested": 25,
        "client_ip": "203.0.113.10",
    })
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"


def test_report_pdf(client):
    r = client.get("/report/paytrust-partner.com.pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"
    assert len(r.content) > 5000


def test_graph_endpoint(client):
    r = client.get("/graph")
    assert r.status_code == 200
    body = r.json()
    assert any(n["kind"] == "company" for n in body["nodes"])
    assert any(n["id"] == "paytrust-partner.com" for n in body["nodes"])


def test_rag_lookup(client):
    r = client.get("/rag/clause/%C2%A78(5)")  # §8(5) URL-encoded
    assert r.status_code == 200
    assert "reasonable" in r.json()["excerpt"].lower() or "safeguards" in r.json()["excerpt"].lower()


def test_rag_ask(client):
    r = client.post("/rag/ask", json={"query": "when must a breach be notified to the Board?"})
    assert r.status_code == 200
    body = r.json()
    assert body["answer"]
    assert body["citations"]
    assert any("8(6)" in c["section"] or "breach" in c["excerpt"].lower() for c in body["citations"])


def test_canary_mint_and_trip(client):
    v = "paytrust-partner.com"
    r = client.post("/canary/mint", json={"vendor": v, "endpoint": "reporting/export-legacy"})
    assert r.status_code == 200
    tok_id = r.json()["id"]
    r = client.post(f"/canary/trip/{tok_id}", json={"from_ip": "198.51.100.9"})
    assert r.status_code == 200
    assert r.json()["triggered"] is True


def test_unknown_vendor_no_mock_cross_contamination(client):
    """A random domain must NOT return paytrust-partner.com's mock findings."""
    r = client.post("/scan", json={"vendor": "random-unrelated-example-xyz.invalid"})
    assert r.status_code == 200
    findings = r.json()["findings"]
    # No leaked Redis/HIBP findings from the demo corpus should appear
    assert not any(f["id"].startswith(("f-", "s-", "h-", "d-")) for f in findings)


def test_fourth_demo_vendor_available(client):
    """databridge-cloud.com is our cross-border / cloud vendor demo case."""
    r = client.post("/scan", json={"vendor": "databridge-cloud.com"})
    assert r.status_code == 200
    body = r.json()
    assert len(body["findings"]) >= 5
    # Must trigger §16 (cross-border) mapping
    assert any(m["clause"] == "§16" for m in body["dpdp"])


def test_root_exposes_ai_and_engines(client):
    r = client.get("/")
    body = r.json()
    assert "integrations" in body
    assert "ai" in body["integrations"]
    # v3.1: crt.sh / DNS / TLS are always-on live integrations (no key required)
    assert body["integrations"]["crt_sh"] is True
    assert body["integrations"]["dns"] is True
    assert body["integrations"]["tls"] is True
    assert "dpdp_rag" in body["engines"]
    # v3.1: expanded RAG corpus (Act + Rules 2025)
    assert body["engines"]["dpdp_rag"]["passages"] >= 40


def test_canary_list(client):
    v = "paytrust-partner.com"
    client.post("/canary/mint", json={"vendor": v, "endpoint": "reporting/export-legacy-2"})
    r = client.get(f"/canary?vendor={v}")
    assert r.status_code == 200
    assert len(r.json()) >= 1


# -------------------------------------------------------------- v3.0 upgrades
def test_framework_crosswalk(client):
    r = client.get("/framework/crosswalk")
    assert r.status_code == 200
    body = r.json()
    assert "iso27001" in body["frameworks"]
    assert body["crosswalk"]["§8(5)"]["iso27001"]


def test_contract_intel_flags_missing_clauses(client):
    weak = (
        "This agreement covers vendor services. Vendor will use best efforts to secure data. "
        "Vendor may store data in United States data centers."
    )
    r = client.post("/contract/analyze", json={"contract_text": weak})
    assert r.status_code == 200
    body = r.json()
    # At least breach notification and cross-border and audit should be missing or flagged
    statuses = {g["section"]: g["status"] for g in body["gaps"]}
    assert statuses.get("§8(6)") == "red"
    assert statuses.get("§16") in ("red", "amber")
    assert body["potential_penalty_inr"] > 0
    assert body["coverage_pct"] < 100
    assert any(g["rag_quote"] for g in body["gaps"])


def test_contract_intel_detects_good_clauses(client):
    good = (
        "Processor shall Process Personal Data only for the purposes of the Services. "
        "Processor shall implement reasonable security safeguards, including encryption "
        "at rest and encryption in transit. Processor shall notify Controller within 24 hours "
        "of any personal data breach. Data will be deleted within 30 days of termination; "
        "retention period is strictly limited. All personal data shall reside in India. "
        "Data subject rights will be supported. Lawful basis and consent of the data principal "
        "will be ensured. A grievance officer and data protection officer are appointed. "
        "Processor grants audit rights to Controller."
    )
    r = client.post("/contract/analyze", json={"contract_text": good})
    body = r.json()
    assert body["coverage_pct"] >= 50


def test_playbook_endpoint(client):
    r = client.get("/playbook/paytrust-partner.com")
    assert r.status_code == 200
    body = r.json()
    assert body["vendor"] == "paytrust-partner.com"
    assert body["total_items"] >= 1
    assert body["total_savings_inr"] > 0
    # Every item carries a crosswalk
    assert all("crosswalk" in it for it in body["items"])


def test_portfolio_endpoint(client):
    r = client.get("/portfolio")
    assert r.status_code == 200
    body = r.json()
    assert body["vendors_tracked"] >= 1
    assert "framework_coverage" in body
    assert body["framework_coverage"]["catalog"]["iso27001"]


def test_kpis_endpoint(client):
    r = client.get("/kpis")
    assert r.status_code == 200
    body = r.json()
    assert "attacks_blocked" in body
    assert "savings_inr" in body


def test_bulk_vendor_scan(client):
    r = client.post("/vendors/bulk", json={"vendors": [
        "paytrust-partner.com", "shopquick-vendor.com"
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert all("vendor" in item for item in body["results"])


def test_incident_pdf_for_recent_alert(client):
    # Make sure we have an alert: reset gateway, activate, trigger a block
    v = "paytrust-partner.com"
    client.post(f"/gateway/reset/{v}")
    client.post("/gateway/activate", json={
        "vendor": v, "scope": ["reporting"], "max_records_per_request": 500,
    })
    resp = client.post("/gateway/proxy", json={
        "vendor": v, "endpoint": "reporting/export", "records_requested": 15000,
        "client_ip": "203.0.113.44",
    }).json()
    alert_id = resp["event"]["id"]
    r = client.get(f"/incident/{alert_id}.pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"


def test_scan_response_includes_crosswalk(client):
    r = client.post("/scan", json={"vendor": "paytrust-partner.com"})
    body = r.json()
    assert any(m.get("crosswalk", {}).get("iso27001") for m in body["dpdp"])


# -------------------------------------------------------------- v3.1 upgrades
def test_contract_intel_has_confidence_and_trace(client):
    """v3.1: every gap returns a confidence score + evidence/red-flag trace
    with offsets so judges can reproduce the verdict."""
    weak = (
        "This agreement covers vendor services. Vendor will use best efforts to "
        "secure data. Vendor may store data in United States data centers. "
        "Vendor may target minors with personalised ads for children."
    )
    r = client.post("/contract/analyze", json={"contract_text": weak})
    body = r.json()
    for g in body["gaps"]:
        assert "confidence" in g and 0.0 < g["confidence"] <= 0.99
        assert "evidence_trace" in g
        assert "red_flags_trace" in g
    # v3.1 rules must be present
    sections = {g["section"] for g in body["gaps"]}
    assert {"§9", "§17", "§8(3)"}.issubset(sections)
    # Red flag on §9 (children profiling) should have a populated trace with a
    # regex matched string.
    child_rows = [g for g in body["gaps"] if g["section"] == "§9"]
    assert any(
        any("matched" in t for t in g.get("red_flags_trace", []))
        for g in child_rows
    )


def test_osint_live_endpoint(client):
    """v3.1: /osint/live/{vendor} calls crt.sh directly — the response must
    include the verify_url so a judge can reproduce the query, even when the
    external service is unreachable."""
    r = client.get("/osint/live/example.com")
    assert r.status_code == 200
    body = r.json()
    assert body["source"].startswith("crt.sh")
    assert "verify_url" in body and "crt.sh" in body["verify_url"]
    assert "latency_ms" in body
    assert isinstance(body["subdomains"], list)


def test_benchmark_ledger(client):
    """v3.1: the Evidence Ledger must expose 3 canned DPAs (strong/ambiguous/weak)
    and every detail call must return full gap analysis with evidence trace."""
    r = client.get("/benchmark/dpas")
    assert r.status_code == 200
    ids = {d["id"] for d in r.json()["dpas"]}
    assert ids == {"strong-dpa", "ambiguous-dpa", "weak-dpa"}
    # Strong DPA ≥ 60% coverage; weak DPA ≤ 25%
    strong = client.get("/benchmark/dpas/strong-dpa").json()
    assert strong["analysis"]["coverage_pct"] >= 60
    weak = client.get("/benchmark/dpas/weak-dpa").json()
    assert weak["analysis"]["coverage_pct"] <= 25
    assert weak["analysis"]["red_count"] >= 3


def test_scan_history_and_diff(client):
    """v3.1: repeat-scanning a vendor builds a history, and /scan/{v}/diff
    returns a structured diff comparing the latest two snapshots."""
    v = "databridge-cloud.com"
    # First scan (baseline) — already executed earlier via test_scan_unknown_vendor.
    # Make sure we have at least one fresh scan then a second snapshot.
    client.post("/scan", json={"vendor": v})
    client.post("/scan", json={"vendor": v})

    hist = client.get(f"/scan/{v}/history").json()
    assert hist["count"] >= 2
    assert all("score" in row and "exposure_inr" in row for row in hist["history"])

    d = client.get(f"/scan/{v}/diff").json()
    assert "summary" in d
    assert "score_delta" in d
    # Schema coverage: every expected key is present.
    for k in (
        "new_findings",
        "resolved_findings",
        "unchanged_findings",
        "new_clauses",
        "resolved_clauses",
    ):
        assert k in d

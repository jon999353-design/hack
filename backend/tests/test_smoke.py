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
    assert body["version"].startswith("2.")
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
    assert "dpdp_rag" in body["engines"]
    assert body["engines"]["dpdp_rag"]["passages"] >= 10


def test_canary_list(client):
    v = "paytrust-partner.com"
    client.post("/canary/mint", json={"vendor": v, "endpoint": "reporting/export-legacy-2"})
    r = client.get(f"/canary?vendor={v}")
    assert r.status_code == 200
    assert len(r.json()) >= 1

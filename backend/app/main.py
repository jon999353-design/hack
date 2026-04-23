"""VendorGuard AI — FastAPI entrypoint.

Run:  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
Docs: http://localhost:8000/docs
"""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sse_starlette.sse import EventSourceResponse

from app import __version__
from app.config import settings
from app.modules import (
    ai_risk,
    alerts,
    anomaly,
    canary,
    contract,
    dpdp,
    events,
    framework,
    gateway,
    incident,
    osint,
    playbook,
    portfolio,
    rag,
    report,
    store,
    trust_score,
)
from app.schemas import (
    ActivateGatewayRequest,
    AlertEvent,
    BulkScanRequest,
    CanaryToken,
    ContractAnalyzeRequest,
    GatewayStatus,
    GraphEdge,
    GraphNode,
    GraphResponse,
    ProxyRequest,
    ScanResponse,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await store.init_db()
    # Warm the ML model + RAG retriever so the first request isn't slow.
    anomaly.model()
    rag.retriever()
    yield


app = FastAPI(
    title="VendorGuard AI",
    description=(
        "Vendor Access Control Plane for DPDP-compliant India. "
        "Scan, score, gateway-protect and auto-respond — with every finding "
        "mapped to a DPDP Act clause and ₹ penalty. Powered by ProjectDiscovery "
        "nuclei, scikit-learn IsolationForest and a bundled DPDP Act RAG retriever."
    ),
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------ root
@app.get("/")
def root() -> dict:
    return {
        "name": "VendorGuard AI",
        "version": __version__,
        "tagline": "The only vendor risk scanner that speaks DPDP.",
        "docs": "/docs",
        "integrations": {
            "crt_sh": True,  # always live: public CT-log service, no key
            "dns": True,     # always live: TXT/MX/NS/DMARC/SPF lookups
            "tls": True,     # always live: cert chain + expiry
            "shodan": settings.has_shodan,
            "hibp": settings.has_hibp,
            "virustotal": settings.has_virustotal,
            "nuclei": settings.has_nuclei,
            "ai": settings.has_ai,
            "whatsapp": settings.has_twilio,
            "webhook": settings.has_webhook,
        },
        "layers": {
            "L1_pre_onboarding": "OSINT scan (Shodan/HIBP/crt.sh/VT/DNS/TLS/nuclei)",
            "L2_trust_score": "Weighted-and-capped 0-100 explainable scorer",
            "L3_dpdp_mapper": "Findings → DPDP clauses + RAG quotes",
            "L4_gateway": "IsolationForest + policy + autonomous response",
            "L5_contract_intel": "DPA gap analysis + rewrite suggestions",
        },
        "engines": {
            "behavioural_ml": anomaly.model().summary(),
            "dpdp_rag": rag.retriever().stats(),
            "framework_crosswalk": framework.frameworks_catalog(),
        },
        "demo_mode": settings.demo_mode,
    }


@app.get("/health")
def health() -> dict:
    return {"ok": True, "version": __version__}


# ------------------------------------------------------------------ scan
@app.post("/scan", response_model=ScanResponse)
async def scan(payload: dict) -> ScanResponse:
    vendor = (payload.get("vendor") or "").strip().lower()
    if not vendor:
        raise HTTPException(400, "Missing 'vendor' (domain).")

    t0 = time.perf_counter()
    findings = await osint.run_osint(vendor)
    mappings = dpdp.map_findings(findings)
    exposure = dpdp.total_exposure(mappings)
    score = trust_score.compute_score(findings)
    summary = await ai_risk.summarise(vendor, findings, mappings, exposure)
    dt = int((time.perf_counter() - t0) * 1000)

    resp = ScanResponse(
        vendor=vendor,
        scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        duration_ms=dt,
        findings=findings,
        dpdp=mappings,
        ai_summary=summary,
        trust=score,
        total_dpdp_exposure_inr=exposure,
    )
    await store.save_scan(vendor, resp.model_dump())
    events.publish("scans", {"vendor": vendor, "trust": score.model_dump(), "exposure_inr": exposure})
    return resp


@app.get("/scan/{vendor}", response_model=ScanResponse)
async def get_scan(vendor: str) -> ScanResponse:
    vendor = vendor.strip().lower()
    r = await store.load_scan(vendor)
    if not r:
        raise HTTPException(404, f"No scan yet for '{vendor}'. POST /scan first.")
    return ScanResponse.model_validate(r)


@app.get("/vendors")
async def vendors() -> dict:
    return {"vendors": await store.list_vendors()}


# ------------------------------------------------------------------ live OSINT
@app.get("/osint/live/{vendor}")
async def osint_live(vendor: str) -> dict:
    """Live, key-less OSINT for a domain.

    Calls crt.sh (Certificate Transparency public logs) directly and returns the
    raw subdomain list + response time. Judges can verify external data is real
    by comparing against `curl 'https://crt.sh/?q=%25.<vendor>&output=json'`.
    """
    import time as _time
    import httpx as _httpx

    vendor = vendor.strip().lower()
    if not vendor:
        raise HTTPException(400, "Missing vendor")
    url = f"https://crt.sh/?q=%25.{vendor}&output=json"
    t0 = _time.perf_counter()
    entries: list = []
    error = None
    try:
        async with _httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(url, headers={"user-agent": "VendorGuard-AI/3.1"})
            if r.status_code == 200:
                entries = r.json()
            else:
                error = f"crt.sh returned HTTP {r.status_code}"
    except Exception as exc:
        error = repr(exc)
    dt = int((_time.perf_counter() - t0) * 1000)
    subs = sorted({e.get("name_value", "").lower() for e in entries if e.get("name_value")})
    # crt.sh returns multi-line name_value (newline-separated SAN list)
    flat: set[str] = set()
    for s in subs:
        for part in s.split("\n"):
            part = part.strip().strip("*. ")
            if part and "." in part:
                flat.add(part)
    return {
        "vendor": vendor,
        "source": "crt.sh (Certificate Transparency)",
        "verify_url": url,
        "requested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "latency_ms": dt,
        "error": error,
        "subdomain_count": len(flat),
        "subdomains": sorted(flat)[:50],
    }


# ------------------------------------------------------------------ gateway
@app.post("/gateway/activate", response_model=GatewayStatus)
async def gateway_activate(req: ActivateGatewayRequest) -> GatewayStatus:
    return await gateway.activate(req.vendor.lower(), req.scope, req.max_records_per_request)


@app.post("/gateway/reset/{vendor}", response_model=GatewayStatus)
async def gateway_reset(vendor: str) -> GatewayStatus:
    return await gateway.reset(vendor.lower())


@app.get("/gateway/status/{vendor}", response_model=GatewayStatus)
async def gateway_status(vendor: str) -> GatewayStatus:
    return await gateway.status(vendor.lower())


@app.post("/gateway/proxy")
async def gateway_proxy(req: ProxyRequest) -> dict:
    """Simulates a vendor API call through the gateway.

    Hero endpoint: bulk/abnormal request → ML + rule engine decides → autonomous
    response (token revoke, endpoint lock) → WhatsApp/SSE alert → all in real
    (measured) wall-clock time."""
    decision, event = await gateway.enforce_request(
        ProxyRequest(
            vendor=req.vendor.lower(),
            endpoint=req.endpoint,
            records_requested=req.records_requested,
            client_ip=req.client_ip,
        )
    )
    alerted = None
    if event is not None:
        scan_data = await store.load_scan(req.vendor.lower())
        if scan_data and scan_data.get("total_dpdp_exposure_inr"):
            event.dpdp_exposure_inr = int(scan_data["total_dpdp_exposure_inr"])
        alerted = await alerts.dispatch(event)

    return {
        "decision": decision,
        "event": event.model_dump() if event else None,
        "alert": alerted,
    }


# ------------------------------------------------------------------ alerts
@app.get("/alerts", response_model=list[AlertEvent])
async def list_alerts(limit: int = Query(50, ge=1, le=500)) -> list[AlertEvent]:
    rows = await store.recent_alerts(limit)
    return [AlertEvent.model_validate(r) for r in rows]


@app.get("/alerts/stream")
async def alerts_stream(request: Request):
    """Server-Sent Events stream for live dashboards. Subscribes to the
    in-process `alerts` channel (and scans/gateway telemetry)."""
    q_alerts = events.subscribe("alerts")
    q_scans = events.subscribe("scans")
    q_traffic = events.subscribe("gateway.traffic")

    async def event_gen():
        try:
            # Send an immediate hello so the client EventSource fires onopen.
            yield {"event": "hello", "data": '{"ok":true}'}
            while True:
                if await request.is_disconnected():
                    break
                done, pending = await asyncio.wait(
                    {
                        asyncio.create_task(q_alerts.get()),
                        asyncio.create_task(q_scans.get()),
                        asyncio.create_task(q_traffic.get()),
                    },
                    timeout=15,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for p in pending:
                    p.cancel()
                if not done:
                    yield {"event": "ping", "data": "{}"}
                    continue
                for t in done:
                    data = t.result()
                    # Heuristic routing by subscriber source queue
                    # (same payload shape — channel name is informational).
                    yield {"event": "message", "data": data}
        finally:
            events.unsubscribe("alerts", q_alerts)
            events.unsubscribe("scans", q_scans)
            events.unsubscribe("gateway.traffic", q_traffic)

    return EventSourceResponse(event_gen())


# ------------------------------------------------------------------ report
@app.get("/report/{vendor}.pdf")
async def report_pdf(vendor: str):
    vendor = vendor.strip().lower()
    scan = await store.load_scan(vendor)
    if not scan:
        raise HTTPException(404, f"No scan yet for '{vendor}'. POST /scan first.")
    pdf = report.render_pdf(scan)
    filename = f"vendorguard-{vendor}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ------------------------------------------------------------------ graph
@app.get("/graph", response_model=GraphResponse)
async def graph() -> GraphResponse:
    """Nodes = company + scanned vendors. Edges coloured by risk exposure."""
    vendors = await store.list_vendors()
    nodes: list[GraphNode] = [GraphNode(id="__you__", label="Your Company", kind="company")]
    edges: list[GraphEdge] = []
    for v in vendors:
        score = v.get("score")
        band = v.get("band") or "watch"
        nodes.append(GraphNode(
            id=v["vendor"],
            label=v["vendor"],
            kind="vendor",
            score=score,
            band=band,
        ))
        sev = "critical" if band == "block" else ("high" if band == "watch" else "low")
        edges.append(GraphEdge(
            source="__you__",
            target=v["vendor"],
            exposure_inr=int(v.get("exposure_inr") or 0),
            severity=sev,  # type: ignore[arg-type]
        ))
    return GraphResponse(nodes=nodes, edges=edges)


# ------------------------------------------------------------------ RAG
@app.get("/rag/clause/{section}")
async def rag_clause(section: str) -> dict:
    hit = rag.retriever().lookup_clause(section)
    if not hit:
        raise HTTPException(404, f"No DPDP excerpt for {section}")
    return hit


@app.post("/rag/ask")
async def rag_ask(payload: dict) -> dict:
    q = (payload.get("query") or "").strip()
    if not q:
        raise HTTPException(400, "Missing 'query'.")
    return await rag.answer(q)


# ------------------------------------------------------------------ canary
@app.post("/canary/mint", response_model=CanaryToken)
async def canary_mint(payload: dict) -> CanaryToken:
    vendor = (payload.get("vendor") or "").strip().lower()
    endpoint = (payload.get("endpoint") or "reporting/export-legacy").strip()
    if not vendor:
        raise HTTPException(400, "Missing 'vendor'.")
    return await canary.mint(vendor, endpoint)


@app.post("/canary/trip/{token_id}", response_model=CanaryToken)
async def canary_trip(token_id: str, payload: dict | None = None) -> CanaryToken:
    from_ip = (payload or {}).get("from_ip", "0.0.0.0")
    tok = await canary.trip(token_id, from_ip)
    if not tok:
        raise HTTPException(404, "Unknown canary token.")
    # Also fire an alert so the SSE dashboard lights up.
    ev = AlertEvent(
        id=f"canary-{token_id}",
        at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        vendor=tok.vendor,
        severity="critical",
        title=f"Canary token tripped on {tok.endpoint}",
        summary=(
            f"A vendor-issued credential hit a canary endpoint never documented "
            f"to that vendor. Origin IP: {from_ip}."
        ),
        action_taken="Credential quarantined; incident response initiated.",
        dpdp_exposure_inr=0,
        containment_seconds=0.0,
    )
    await alerts.dispatch(ev)
    return tok


@app.get("/canary", response_model=list[CanaryToken])
async def canary_list(vendor: str | None = Query(None)) -> list[CanaryToken]:
    return await canary.list_for(vendor.lower() if vendor else None)


# ------------------------------------------------------------------ framework
@app.get("/framework/crosswalk")
def framework_crosswalk() -> dict:
    """DPDP § → ISO 27001 / SOC 2 / NIST CSF crosswalk."""
    return framework.full_crosswalk()


# ------------------------------------------------------------------ contract intel (Layer 5)
@app.post("/contract/analyze")
async def contract_analyze(req: ContractAnalyzeRequest) -> dict:
    """Drop a vendor DPA → structured DPDP gap list + rewrite suggestions.

    This is Layer 5 (Contract Intelligence) from the deck, now live.
    """
    result = contract.analyze(req.contract_text or "")
    if req.polish_rewrites and settings.has_ai:
        for g in result["gaps"]:
            g["recommended_rewrite"] = await contract.polish_rewrite(
                g["label"], g["recommended_rewrite"]
            )
    return result


# ------------------------------------------------------------------ remediation playbook
@app.get("/playbook/{vendor}")
async def get_playbook(vendor: str) -> dict:
    vendor = vendor.strip().lower()
    scan = await store.load_scan(vendor)
    if not scan:
        raise HTTPException(404, f"No scan yet for '{vendor}'. POST /scan first.")
    return playbook.build_for(scan)


# ------------------------------------------------------------------ executive / portfolio
@app.get("/portfolio")
async def get_portfolio() -> dict:
    """Executive board view — aggregate KPIs across every scanned vendor."""
    return await portfolio.build()


@app.get("/kpis")
async def get_kpis() -> dict:
    """Lightweight KPI tiles for the header ticker (cheap, no crosswalk fanout)."""
    vendors = await store.list_vendors()
    all_alerts = await store.recent_alerts(500)
    blocked = [a for a in all_alerts if a.get("severity") in ("critical", "high")]
    return {
        "vendors_tracked": len(vendors),
        "attacks_blocked": len(blocked),
        "savings_inr": int(sum(int(a.get("dpdp_exposure_inr") or 0) for a in blocked)),
        "total_exposure_inr": int(sum(int(v.get("exposure_inr") or 0) for v in vendors)),
    }


# ------------------------------------------------------------------ bulk vendor onboarding
@app.post("/vendors/bulk")
async def bulk_scan(req: BulkScanRequest) -> dict:
    """Scan up to 25 vendors in parallel — for CSV / multi-vendor onboarding."""
    domains = [v.strip().lower() for v in (req.vendors or []) if v and v.strip()]
    if not domains:
        raise HTTPException(400, "No vendors provided.")
    domains = domains[:25]

    async def _one(d: str) -> dict:
        try:
            findings = await osint.run_osint(d)
            mappings = dpdp.map_findings(findings)
            exposure = dpdp.total_exposure(mappings)
            score = trust_score.compute_score(findings)
            summary = await ai_risk.summarise(d, findings, mappings, exposure)
            resp = ScanResponse(
                vendor=d,
                scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                duration_ms=0,
                findings=findings,
                dpdp=mappings,
                ai_summary=summary,
                trust=score,
                total_dpdp_exposure_inr=exposure,
            )
            await store.save_scan(d, resp.model_dump())
            events.publish(
                "scans",
                {"vendor": d, "trust": score.model_dump(), "exposure_inr": exposure},
            )
            return {
                "vendor": d,
                "score": score.score,
                "band": score.band,
                "exposure_inr": exposure,
                "findings": len(findings),
            }
        except Exception as e:
            return {"vendor": d, "error": str(e)}

    results = await asyncio.gather(*(_one(d) for d in domains))
    return {"count": len(results), "results": results}


# ------------------------------------------------------------------ CERT-In incident report
@app.get("/incident/{alert_id}.pdf")
async def incident_pdf(alert_id: str):
    """Pre-filled CERT-In / DPB 6-hour incident report PDF for an alert."""
    rows = await store.recent_alerts(500)
    alert = next((a for a in rows if a.get("id") == alert_id), None)
    if not alert:
        raise HTTPException(404, f"No alert '{alert_id}'.")
    scan = await store.load_scan(alert.get("vendor", ""))
    pdf = incident.render_pdf(alert, scan)
    filename = f"cert-in-incident-{alert_id}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

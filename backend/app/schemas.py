"""Pydantic models shared across the API."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class Finding(BaseModel):
    id: str
    source: str  # shodan | hibp | crt.sh | virustotal | dns | tls | nuclei | dpdp-rule
    title: str
    description: str
    severity: Severity
    evidence: dict = Field(default_factory=dict)


class DPDPMapping(BaseModel):
    finding_id: str
    clause: str              # e.g. "§8(5)"
    obligation: str          # e.g. "Reasonable security safeguards"
    max_penalty_inr: int     # e.g. 2500000000 (₹250 Cr)
    immediate_action: str
    liability_note: str
    rag_quote: str | None = None   # verbatim excerpt from the Act (P1 RAG)
    rag_citation: str | None = None  # e.g. "DPDP Act 2023, §8(5), Gazette p. 7"
    crosswalk: dict = Field(default_factory=dict)  # ISO27001 / SOC2 / NIST controls


class ScoreBand(BaseModel):
    score: int
    band: Literal["safe", "watch", "block"]
    color: str
    label: str


class ScanResponse(BaseModel):
    vendor: str
    scanned_at: str
    duration_ms: int
    findings: list[Finding]
    dpdp: list[DPDPMapping]
    ai_summary: str
    trust: ScoreBand
    total_dpdp_exposure_inr: int


class ActivateGatewayRequest(BaseModel):
    vendor: str
    scope: list[str] = Field(default_factory=lambda: ["reporting"])
    max_records_per_request: int = 500


class GatewayStatus(BaseModel):
    vendor: str
    active: bool
    scope: list[str]
    max_records_per_request: int
    token_id: str | None = None
    activated_at: str | None = None


class ProxyRequest(BaseModel):
    vendor: str
    endpoint: str
    records_requested: int
    client_ip: str = "203.0.113.42"


class AlertEvent(BaseModel):
    id: str
    at: str
    vendor: str
    severity: Severity
    title: str
    summary: str
    action_taken: str
    dpdp_exposure_inr: int
    containment_seconds: float
    anomaly_score: float | None = None  # IsolationForest score; negative = anomalous


class GraphNode(BaseModel):
    id: str
    label: str
    kind: Literal["company", "vendor"]
    score: int | None = None
    band: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    exposure_inr: int
    severity: Severity


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class CanaryToken(BaseModel):
    id: str
    vendor: str
    endpoint: str
    created_at: str
    triggered: bool = False
    triggered_at: str | None = None
    triggered_from: str | None = None


class RAGAnswer(BaseModel):
    query: str
    answer: str
    citations: list[dict]  # [{section, page, excerpt}]


class ContractAnalyzeRequest(BaseModel):
    contract_text: str
    polish_rewrites: bool = False  # set True to LLM-polish recommended rewrites


class BulkScanRequest(BaseModel):
    vendors: list[str]  # list of domains to scan

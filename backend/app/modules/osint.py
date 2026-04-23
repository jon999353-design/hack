"""OSINT collection: Shodan, HaveIBeenPwned, crt.sh, VirusTotal, DNS, TLS,
ProjectDiscovery nuclei.

Every source gracefully degrades to deterministic mock data when no API key
is configured, so the demo is reliable even on conference WiFi.

In demo mode, live findings are merged with the *vendor-specific* mock corpus
only when the vendor exists in `demo_vendors.json`. Unknown vendors are
scanned live only — no foreign mock findings are grafted in.
"""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
from pathlib import Path
from typing import Any

import dns.asyncresolver
import httpx

from app.config import settings
from app.modules.nuclei import run_nuclei
from app.schemas import Finding

DATA_DIR = Path(__file__).parent.parent / "data"
DEMO_VENDORS = json.loads((DATA_DIR / "demo_vendors.json").read_text())


async def _shodan(domain: str) -> list[Finding]:
    if not settings.has_shodan:
        return []
    url = f"https://api.shodan.io/dns/domain/{domain}?key={settings.shodan_api_key}"
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception:
        return []
    findings: list[Finding] = []
    for sub in data.get("data", [])[:5]:
        if sub.get("type") == "A":
            findings.append(
                Finding(
                    id=f"shodan-{sub.get('subdomain','root')}",
                    source="shodan",
                    title=f"Public host discovered: {sub.get('subdomain') or domain}",
                    description=f"Shodan DNS record → {sub.get('value')}",
                    severity="medium",
                    evidence=sub,
                )
            )
    return findings


async def _hibp(domain: str) -> list[Finding]:
    if not settings.has_hibp:
        return []
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    headers = {
        "hibp-api-key": settings.hibp_api_key,
        "user-agent": "VendorGuard-AI/2.0",
    }
    try:
        async with httpx.AsyncClient(timeout=8.0, headers=headers) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            breaches = r.json()
    except Exception:
        return []
    if not breaches:
        return []
    return [
        Finding(
            id="hibp-domain",
            source="hibp",
            title=f"{len(breaches)} breach(es) touching this domain",
            description=", ".join(b["Name"] for b in breaches[:5]),
            severity="high",
            evidence={"count": len(breaches), "sample": [b["Name"] for b in breaches[:5]]},
        )
    ]


async def _crtsh(domain: str) -> list[Finding]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            entries = r.json()
    except Exception:
        return []
    subs = {e.get("name_value") for e in entries if e.get("name_value")}
    if not subs:
        return []
    sev = "medium" if len(subs) > 10 else "low"
    return [
        Finding(
            id="crtsh-1",
            source="crt.sh",
            title=f"{len(subs)} subdomains in certificate transparency logs",
            description="Subdomains visible in CT logs widen your attack surface.",
            severity=sev,
            evidence={"count": len(subs), "sample": list(subs)[:5]},
        )
    ]


async def _virustotal(domain: str) -> list[Finding]:
    if not settings.has_virustotal:
        return []
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        async with httpx.AsyncClient(timeout=8.0, headers=headers) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception:
        return []
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    if malicious == 0 and suspicious == 0:
        return []
    sev = "critical" if malicious > 0 else "medium"
    return [
        Finding(
            id="vt-1",
            source="virustotal",
            title=f"{malicious + suspicious} reputation vendors flagged domain",
            description=f"{malicious} malicious, {suspicious} suspicious.",
            severity=sev,
            evidence=stats,
        )
    ]


async def _dns_hygiene(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 4.0

    async def _txt(name: str) -> list[str]:
        try:
            answers = await resolver.resolve(name, "TXT")
            return [b"".join(r.strings).decode() for r in answers]
        except Exception:
            return []

    spf = [t for t in await _txt(domain) if t.startswith("v=spf1")]
    dmarc_txts = await _txt(f"_dmarc.{domain}")
    dmarc_policy = None
    for t in dmarc_txts:
        for part in t.split(";"):
            if part.strip().startswith("p="):
                dmarc_policy = part.strip()[2:]
                break
    if not spf:
        findings.append(
            Finding(
                id="dns-spf",
                source="dns",
                title="SPF record missing",
                description="Email senders can spoof this domain.",
                severity="low",
                evidence={"spf": None},
            )
        )
    if dmarc_policy in (None, "none"):
        findings.append(
            Finding(
                id="dns-dmarc",
                source="dns",
                title=f"DMARC policy is '{dmarc_policy or 'missing'}'",
                description="Enforcement should be quarantine or reject.",
                severity="low",
                evidence={"dmarc": dmarc_policy},
            )
        )
    return findings


def _tls_probe(domain: str) -> list[Finding]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version() or ""
                cert = ssock.getpeercert()
    except Exception:
        return []
    findings: list[Finding] = []
    if version in ("TLSv1", "TLSv1.1"):
        findings.append(
            Finding(
                id="tls-legacy",
                source="tls",
                title=f"Legacy protocol {version} negotiated",
                description="Deprecated TLS version in use.",
                severity="medium",
                evidence={"version": version, "cert_subject": str(cert.get("subject", ""))},
            )
        )
    return findings


async def _tls_async(domain: str) -> list[Finding]:
    return await asyncio.to_thread(_tls_probe, domain)


def _mock_findings(vendor: str) -> list[Finding]:
    data = DEMO_VENDORS.get(vendor)
    if data is None:
        return []
    out: list[Finding] = []
    for f in data["findings"]:
        out.append(
            Finding(
                id=f["id"],
                source=f["source"],
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                evidence=f.get("evidence", {}) | {"tag": f.get("tag")},
            )
        )
    return out


async def run_osint(vendor: str) -> list[Finding]:
    """Run all OSINT sources in parallel. In demo mode, mock findings are blended
    ONLY for vendors that exist in `demo_vendors.json` — unknown vendors are
    scanned purely live so the dashboard reflects their real posture."""
    mock = _mock_findings(vendor) if settings.demo_mode else []
    live = await _live_parallel(vendor)
    # De-duplicate by id, preferring live results
    by_id: dict[str, Finding] = {f.id: f for f in mock}
    for f in live:
        by_id[f.id] = f
    return list(by_id.values())


async def _live_parallel(vendor: str) -> list[Finding]:
    tasks: list[Any] = [
        _shodan(vendor),
        _hibp(vendor),
        _crtsh(vendor),
        _virustotal(vendor),
        _dns_hygiene(vendor),
        _tls_async(vendor),
        run_nuclei(vendor),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[Finding] = []
    for r in results:
        if isinstance(r, list):
            out.extend(r)
    return out

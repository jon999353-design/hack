"""ProjectDiscovery nuclei integration.

If the `nuclei` binary is on PATH, we execute it as a subprocess with a
curated tag set and parse its JSON-lines output into Finding objects.

If the binary is absent (common on fresh VMs / hackathon WiFi), we return
an empty list and let the upstream demo/mock layer supply example results.
Install locally with:

    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from app.config import settings
from app.schemas import Finding


SEVERITY_MAP = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "low",
}


def _severity(raw: str | None) -> str:
    return SEVERITY_MAP.get((raw or "low").lower(), "low")


async def run_nuclei(domain: str, *, timeout_s: float = 20.0) -> list[Finding]:
    if not settings.has_nuclei:
        return []
    target = f"https://{domain}"
    cmd = [
        settings.nuclei_bin,
        "-u", target,
        "-tags", settings.nuclei_template_tags,
        "-silent",
        "-jsonl",
        "-rate-limit", "50",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            return []
    except FileNotFoundError:
        return []

    findings: list[Finding] = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {})
        template_id = row.get("template-id") or row.get("templateID") or "unknown"
        findings.append(
            Finding(
                id=f"nuclei-{template_id}",
                source="nuclei",
                title=f"{info.get('name', template_id)} matched on {row.get('host', domain)}",
                description=(info.get("description") or "").strip() or "Nuclei template match.",
                severity=_severity(info.get("severity")),
                evidence={
                    "template": template_id,
                    "matched_at": row.get("matched-at"),
                    "host": row.get("host"),
                    "tags": info.get("tags"),
                    "tag": "cve_exposure" if template_id.lower().startswith("cve-") else "misconfig_exposure",
                },
            )
        )
    return findings

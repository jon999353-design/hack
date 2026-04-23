"""AI Risk Engine.

Takes raw findings + DPDP mappings and produces a plain-English business-risk
summary a CISO can paste into a board note. Provider is picked by
`settings.ai_provider`:

    anthropic   → Anthropic Claude (default; best quality for DPDP tone)
    openai      → OpenAI (or any OpenAI-compatible gateway via OPENAI_BASE_URL)
    openrouter  → OpenRouter (OpenAI-compatible; any hosted model)
    <anything else / missing key> → deterministic template fallback

Every code path is wrapped in try/except so a bad key or a rate limit NEVER
breaks the /scan endpoint — the template fallback always runs.
"""
from __future__ import annotations

from app.config import settings
from app.schemas import DPDPMapping, Finding
from app.modules.dpdp import format_inr

SYSTEM_PROMPT = (
    "You are a CISO advisor specialising in India's DPDP Act 2023. "
    "Given raw vendor security findings and DPDP clause mappings, write a "
    "5-sentence board-ready risk summary. Be specific. Cite clauses. Quote "
    "₹ exposure. End with one sentence on recommended action."
)


def _template_summary(
    vendor: str,
    findings: list[Finding],
    dpdp: list[DPDPMapping],
    exposure_inr: int,
) -> str:
    top = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}[f.severity],
    )[:3]
    top_txt = "; ".join(f"{f.title} ({f.severity})" for f in top) or "no material findings"
    clauses = sorted({m.clause for m in dpdp})
    clause_txt = ", ".join(clauses) or "no DPDP clauses triggered"
    return (
        f"Vendor {vendor} carries material DPDP exposure of {format_inr(exposure_inr)}. "
        f"Most critical technical issues: {top_txt}. "
        f"Clauses triggered: {clause_txt}. "
        "Under §8(5), the data fiduciary (your company) is directly liable for a vendor's failure. "
        "Recommendation: route this vendor through the VendorGuard Access Gateway with a <500-records "
        "rate limit and manual approval on bulk exports, and remediate the critical findings within 14 days."
    )


async def _anthropic_summary(prompt: str) -> str | None:
    try:
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        msg = await client.messages.create(
            model=settings.anthropic_model,
            max_tokens=400,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        parts = [b.text for b in msg.content if getattr(b, "type", "") == "text"]
        return "".join(parts).strip() or None
    except Exception:
        return None


async def _openai_compatible_summary(
    prompt: str,
    *,
    api_key: str,
    base_url: str,
    model: str,
    extra_headers: dict | None = None,
) -> str | None:
    """Works for both api.openai.com and any OpenAI-compatible gateway
    (OpenRouter, Groq, Together, Fireworks, Ollama, vLLM, LM Studio …)."""
    try:
        from openai import AsyncOpenAI

        kwargs: dict = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        if extra_headers:
            kwargs["default_headers"] = extra_headers
        client = AsyncOpenAI(**kwargs)
        resp = await client.chat.completions.create(
            model=model,
            max_tokens=400,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return (resp.choices[0].message.content or "").strip() or None
    except Exception:
        return None


async def summarise(
    vendor: str,
    findings: list[Finding],
    dpdp: list[DPDPMapping],
    exposure_inr: int,
) -> str:
    facts = {
        "vendor": vendor,
        "exposure_inr_human": format_inr(exposure_inr),
        "findings": [f.model_dump() for f in findings],
        "dpdp_clauses": [m.model_dump() for m in dpdp],
    }
    prompt = f"Facts:\n{facts}\n\nWrite the 5-sentence summary now."

    provider = (settings.ai_provider or "").lower()

    if provider == "anthropic" and settings.anthropic_api_key:
        out = await _anthropic_summary(prompt)
        if out:
            return out

    if provider == "openai" and settings.openai_api_key:
        out = await _openai_compatible_summary(
            prompt,
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
            model=settings.openai_model,
        )
        if out:
            return out

    if provider == "openrouter" and settings.openrouter_api_key:
        out = await _openai_compatible_summary(
            prompt,
            api_key=settings.openrouter_api_key,
            base_url=settings.openrouter_base_url,
            model=settings.openrouter_model,
            # OpenRouter attribution headers — optional, helps their dashboard.
            extra_headers={
                "HTTP-Referer": "https://github.com/Akshu3104/vendorguard-ai",
                "X-Title": "VendorGuard AI",
            },
        )
        if out:
            return out

    return _template_summary(vendor, findings, dpdp, exposure_inr)

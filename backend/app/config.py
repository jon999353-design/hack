"""Central config loaded from environment variables."""
from __future__ import annotations

import shutil

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # OSINT
    shodan_api_key: str = ""
    hibp_api_key: str = ""
    virustotal_api_key: str = ""

    # AI — Anthropic, OpenAI, and any OpenAI-compatible provider (OpenRouter,
    # Groq, Together, Fireworks, local Ollama/LM Studio, etc.) are supported.
    # Pick ONE via `ai_provider`. Missing keys fall back to a deterministic
    # template summary so the demo always runs.
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-5-sonnet-latest"
    openai_api_key: str = ""
    openai_base_url: str = ""  # set for OpenAI-compatible gateways; leave blank for api.openai.com
    openai_model: str = "gpt-4o-mini"
    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "anthropic/claude-3.5-sonnet"
    ai_provider: str = "anthropic"  # anthropic | openai | openrouter | mock

    # Nuclei (ProjectDiscovery)
    nuclei_bin: str = "nuclei"
    nuclei_template_tags: str = "cve,exposure,misconfig"

    # RAG
    dpdp_act_pdf_path: str = ""

    # Twilio WhatsApp
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_whatsapp_from: str = "whatsapp:+14155238886"
    alert_whatsapp_to: str = ""

    # App
    app_env: str = "dev"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    demo_mode: bool = True
    sqlite_path: str = "./vendorguard.db"

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan_api_key)

    @property
    def has_hibp(self) -> bool:
        return bool(self.hibp_api_key)

    @property
    def has_virustotal(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def has_ai(self) -> bool:
        if self.ai_provider == "anthropic":
            return bool(self.anthropic_api_key)
        if self.ai_provider == "openai":
            return bool(self.openai_api_key)
        if self.ai_provider == "openrouter":
            return bool(self.openrouter_api_key)
        return False

    @property
    def has_twilio(self) -> bool:
        return bool(self.twilio_account_sid and self.twilio_auth_token)

    @property
    def has_nuclei(self) -> bool:
        """True if the `nuclei` binary is on PATH."""
        return shutil.which(self.nuclei_bin) is not None


settings = Settings()

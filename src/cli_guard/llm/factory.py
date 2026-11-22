"""Factory for instantiating the configured pluggable LLM provider."""

from __future__ import annotations

from cli_guard.config import Settings
from cli_guard.llm.anthropic import AnthropicProvider
from cli_guard.llm.base import LLMProvider
from cli_guard.llm.gemini import GeminiProvider
from cli_guard.llm.openai_compat import OpenAICompatProvider


def create_provider(settings: Settings) -> LLMProvider | None:
    """Create the configured LLM provider, or return None if credentials are not configured."""
    preset = settings.resolved_preset
    api_key = settings.effective_api_key

    # Local Ollama / custom endpoints may not require an API key
    requires_key = preset.name not in {"ollama", "custom"}
    if requires_key and not api_key:
        return None

    if preset.kind == "anthropic":
        return AnthropicProvider(
            base_url=settings.effective_base_url,
            api_key=api_key,
            timeout=settings.http_timeout_seconds + 15.0,
        )
    if preset.kind == "gemini":
        return GeminiProvider(
            base_url=settings.effective_base_url,
            api_key=api_key,
            timeout=settings.http_timeout_seconds + 15.0,
        )
    return OpenAICompatProvider(
        name=preset.name,
        base_url=settings.effective_base_url,
        api_key=api_key,
        timeout=settings.http_timeout_seconds + 15.0,
    )

"""Construct the configured model provider."""

from __future__ import annotations

from ..config import ModelConfig
from .base import LLMProvider


def build_provider(cfg: ModelConfig, splunk_service=None) -> LLMProvider:
    provider = cfg.provider.lower().strip()

    if provider == "ollama":
        from .ollama_provider import OllamaProvider

        return OllamaProvider(cfg.ollama_base_url, cfg.ollama_model)

    if provider in {"vllm", "openai", "openai_compat"}:
        from .openai_compat import OpenAICompatProvider

        return OpenAICompatProvider(cfg.vllm_base_url, cfg.vllm_model)

    if provider == "splunk_hosted":
        from .splunk_hosted import SplunkHostedProvider

        if splunk_service is None:
            raise ValueError(
                "splunk_hosted provider needs a connected Splunk service. "
                "Use ollama or vllm on Splunk Enterprise."
            )
        return SplunkHostedProvider(splunk_service, cfg.splunk_hosted_model, cfg.temperature)

    if provider == "replay":
        from .replay import ReplayProvider

        return ReplayProvider(cfg.name)

    raise ValueError(f"Unknown model provider: {cfg.provider!r}")

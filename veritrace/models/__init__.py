"""Pluggable model providers for Veritrace.

The agent depends only on the LLMProvider interface, so the reasoning engine can
be the Foundation-Sec model served locally through Ollama or vLLM, the
Splunk-hosted Foundation-Sec model on Splunk Cloud, or a deterministic replay
provider that needs no GPU and no network for tests and offline demos.
"""

from .base import CompletionResult, LLMProvider, Message
from .factory import build_provider

__all__ = ["CompletionResult", "LLMProvider", "Message", "build_provider"]

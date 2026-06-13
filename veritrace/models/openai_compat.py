"""OpenAI-compatible chat provider.

Covers vLLM serving the Foundation-Sec weights (the production-grade local
serving path), and any other endpoint that speaks the /chat/completions API.
"""

from __future__ import annotations

import time

import httpx

from .base import CompletionResult, LLMProvider, Message


class OpenAICompatProvider(LLMProvider):
    name = "openai_compat"

    def __init__(self, base_url: str, model: str, api_key: str = "not-needed", timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    def complete(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        tag: str = "",
        json_mode: bool = False,
    ) -> CompletionResult:
        payload: dict = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            # vLLM and most OpenAI-compatible servers honor this to force a JSON object.
            payload["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        start = time.perf_counter()
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        latency_ms = int((time.perf_counter() - start) * 1000)
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return CompletionResult(
            text=text,
            tokens_prompt=int(usage.get("prompt_tokens", 0)),
            tokens_completion=int(usage.get("completion_tokens", 0)),
            latency_ms=latency_ms,
            raw=data,
        )

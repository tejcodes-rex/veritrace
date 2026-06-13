"""Ollama provider. Default path for running Foundation-Sec locally.

Foundation-Sec-1.1-8B is the Cisco Foundation AI cybersecurity model that
Splunk hosts on Splunk Cloud. Splunk Enterprise cannot reach the hosted copy,
so on Enterprise we serve the same open weights locally. A 4-bit build of the
8B model fits in roughly 5 GB of VRAM, which runs on a single laptop GPU.
"""

from __future__ import annotations

import time

import httpx

from .base import CompletionResult, LLMProvider, Message


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, base_url: str, model: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
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
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if json_mode:
            # Constrains the decode to a single JSON object. Foundation-Sec-8B is
            # far more reliable with this on, so the agent rarely falls back.
            payload["format"] = "json"
        start = time.perf_counter()
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
        latency_ms = int((time.perf_counter() - start) * 1000)
        text = (data.get("message") or {}).get("content", "")
        return CompletionResult(
            text=text,
            tokens_prompt=int(data.get("prompt_eval_count", 0)),
            tokens_completion=int(data.get("eval_count", 0)),
            latency_ms=latency_ms,
            raw=data,
        )

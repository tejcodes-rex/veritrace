"""Deterministic replay provider.

Serves the reasoning recorded in scenarios.py keyed by the decision tag the
agent passes. It needs no GPU and no network, so tests and the offline demo run
anywhere and produce the same investigation every time. The searches the agent
runs are still executed for real against Splunk, so the evidence is live even
when the reasoning is replayed.
"""

from __future__ import annotations

import json

from .. import scenarios
from .base import CompletionResult, LLMProvider, Message


def _build_script() -> dict[str, str]:
    script: dict[str, str] = {"triage": json.dumps(scenarios.TRIAGE)}
    for step in scenarios.STEPS:
        payload = {k: v for k, v in step.items() if k != "tag"}
        script[step["tag"]] = json.dumps(payload)
    script["verdict"] = json.dumps(scenarios.VERDICT)
    script["detection"] = json.dumps(scenarios.DETECTION)
    return script


class ReplayProvider(LLMProvider):
    name = "replay"

    def __init__(self, model: str = "foundation-sec-replay"):
        self.model = model
        self._script = _build_script()

    def complete(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        tag: str = "",
        json_mode: bool = False,
    ) -> CompletionResult:
        text = self._script.get(tag, "{}")
        # token counts approximate the recorded answer so ledger metrics stay realistic
        approx_completion = max(1, len(text) // 4)
        approx_prompt = sum(max(1, len(m.content) // 4) for m in messages)
        return CompletionResult(
            text=text,
            tokens_prompt=approx_prompt,
            tokens_completion=approx_completion,
            latency_ms=3,
            raw={"tag": tag, "replay": True},
        )

"""Splunk-hosted model provider.

On Splunk Cloud the Foundation-Sec model is reachable from SPL through the AI
Toolkit ``ai`` command, with no GPU to manage and no data leaving the Splunk
boundary. This provider routes a prompt through that command using the Splunk
SDK and reads the generated text back out of the result row.

This path requires Splunk Cloud with the AI Toolkit. On Splunk Enterprise use
the ollama or vllm provider, which serves the same open weights locally.
"""

from __future__ import annotations

import time

from .base import CompletionResult, LLMProvider, Message


def _flatten(messages: list[Message]) -> str:
    parts = []
    for m in messages:
        prefix = {"system": "Instructions", "user": "Task", "assistant": "Assistant"}.get(
            m.role, m.role.title()
        )
        parts.append(f"{prefix}:\n{m.content}")
    return "\n\n".join(parts)


def _spl_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class SplunkHostedProvider(LLMProvider):
    name = "splunk_hosted"
    _result_fields = ("ai_response", "response", "result", "text", "generation", "completion")

    def __init__(self, service, model: str, temperature: float = 0.2):
        # ``service`` is a connected splunklib.client.Service
        self.service = service
        self.model = model
        self.temperature = temperature

    def complete(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        tag: str = "",
        json_mode: bool = False,
    ) -> CompletionResult:
        import splunklib.results as results  # lazy, only needed on the Cloud path

        prompt = _spl_escape(_flatten(messages))
        spl = (
            '| makeresults '
            f'| eval prompt="{prompt}" '
            f'| ai prompt="{{prompt}}" provider=splunk_hosted '
            f'model={self.model} temperature={temperature}'
        )
        start = time.perf_counter()
        response = self.service.jobs.oneshot(spl, output_mode="json", count=1)
        text = ""
        for event in results.JSONResultsReader(response):
            if isinstance(event, dict):
                for field in self._result_fields:
                    if field in event and event[field]:
                        text = str(event[field])
                        break
                if not text:
                    # fall back to the last non-internal field on the row
                    for k, v in event.items():
                        if not k.startswith("_") and isinstance(v, str) and v:
                            text = v
                break
        latency_ms = int((time.perf_counter() - start) * 1000)
        return CompletionResult(text=text, latency_ms=latency_ms, raw={"spl": spl})

"""Provider interface and shared parsing helpers."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Message:
    role: str  # system | user | assistant
    content: str


@dataclass
class CompletionResult:
    text: str
    tokens_prompt: int = 0
    tokens_completion: int = 0
    latency_ms: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


class LLMProvider(ABC):
    """Minimal chat-completion contract every provider implements."""

    name: str = "base"
    model: str = "unknown"

    @abstractmethod
    def complete(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        tag: str = "",
        json_mode: bool = False,
    ) -> CompletionResult:
        """Return a chat completion.

        ``tag`` names the decision point in the investigation (for example
        ``plan`` or ``verdict``). Live providers ignore it; the replay provider
        uses it to return the matching recorded answer.

        ``json_mode`` asks the backend to constrain output to a JSON object when
        it supports it. Small instruct models are far more reliable with this on,
        so the agent rarely has to fall back to its playbook.
        """
        ...

    def complete_json(
        self,
        messages: list[Message],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        tag: str = "",
    ) -> tuple[dict[str, Any], CompletionResult]:
        """Run a completion and parse the first JSON object out of the reply.

        Small instruct models wrap JSON in prose or code fences, so the parser
        is deliberately forgiving. A parse failure returns an empty dict and the
        caller falls back to its deterministic playbook.
        """
        result = self.complete(
            messages, temperature=temperature, max_tokens=max_tokens, tag=tag, json_mode=True
        )
        return extract_json(result.text), result


def extract_json(text: str) -> dict[str, Any]:
    """Pull a JSON object out of arbitrary model text.

    Handles fenced ```json blocks, leading prose, and trailing commentary by
    scanning for the first balanced curly-brace span.
    """
    if not text:
        return {}

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        candidate = fenced.group(1)
        parsed = _try_load(candidate)
        if parsed is not None:
            return parsed

    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    parsed = _try_load(text[start : i + 1])
                    if parsed is not None:
                        return parsed
                    break
        start = text.find("{", start + 1)
    return {}


def _try_load(candidate: str) -> dict[str, Any] | None:
    try:
        value = json.loads(candidate)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        # tolerate trailing commas, a common small-model slip
        cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
        try:
            value = json.loads(cleaned)
            return value if isinstance(value, dict) else None
        except json.JSONDecodeError:
            return None

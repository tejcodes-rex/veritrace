"""Central configuration, loaded from environment with safe defaults.

Every default is chosen so a clean checkout of the bundled Docker stack runs
without edits. Override anything through a .env file or real environment vars.
Environment is read when load_config() is called, not at import, so a process
that sets a variable before building its config sees it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")


def _b(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SplunkConfig:
    host: str = "localhost"
    mgmt_port: int = 8089
    hec_port: int = 8088
    web_port: int = 8000
    username: str = "admin"
    password: str = "Veritrace!2026"
    hec_token: str = "00000000-feed-feed-feed-000000000000"
    verify_tls: bool = False
    index_security: str = "security"
    index_ledger: str = "veritrace_ledger"
    index_detections: str = "veritrace_detections"

    @classmethod
    def from_env(cls) -> "SplunkConfig":
        return cls(
            host=os.getenv("SPLUNK_HOST", "localhost"),
            mgmt_port=int(os.getenv("SPLUNK_MGMT_PORT", "8089")),
            hec_port=int(os.getenv("SPLUNK_HEC_PORT", "8088")),
            web_port=int(os.getenv("SPLUNK_WEB_PORT", "8000")),
            username=os.getenv("SPLUNK_USERNAME", "admin"),
            password=os.getenv("SPLUNK_PASSWORD", "Veritrace!2026"),
            hec_token=os.getenv("SPLUNK_HEC_TOKEN", "00000000-feed-feed-feed-000000000000"),
            verify_tls=_b("SPLUNK_VERIFY_TLS", False),
            index_security=os.getenv("SPLUNK_INDEX_SECURITY", "security"),
            index_ledger=os.getenv("SPLUNK_INDEX_LEDGER", "veritrace_ledger"),
            index_detections=os.getenv("SPLUNK_INDEX_DETECTIONS", "veritrace_detections"),
        )

    @property
    def hec_url(self) -> str:
        return f"https://{self.host}:{self.hec_port}/services/collector"

    @property
    def web_url(self) -> str:
        return f"http://{self.host}:{self.web_port}"


@dataclass(frozen=True)
class McpConfig:
    transport: str = "sse"
    url: str = "http://localhost:8052/sse"

    @classmethod
    def from_env(cls) -> "McpConfig":
        return cls(
            transport=os.getenv("MCP_TRANSPORT", "sse"),
            url=os.getenv("MCP_URL", "http://localhost:8052/sse"),
        )


@dataclass(frozen=True)
class ModelConfig:
    provider: str = "replay"
    name: str = "foundation-sec"
    temperature: float = 0.2
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"
    vllm_base_url: str = "http://localhost:8000/v1"
    vllm_model: str = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct"
    splunk_hosted_model: str = "foundation-sec-1.1-8b-instruct"

    @classmethod
    def from_env(cls) -> "ModelConfig":
        return cls(
            provider=os.getenv("VERITRACE_MODEL_PROVIDER", "replay"),
            name=os.getenv("VERITRACE_MODEL_NAME", "foundation-sec"),
            temperature=float(os.getenv("VERITRACE_MODEL_TEMPERATURE", "0.2")),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            ollama_model=os.getenv("OLLAMA_MODEL", "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"),
            vllm_base_url=os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1"),
            vllm_model=os.getenv("VLLM_MODEL", "fdtn-ai/Foundation-Sec-1.1-8B-Instruct"),
            splunk_hosted_model=os.getenv("SPLUNK_HOSTED_MODEL", "foundation-sec-1.1-8b-instruct"),
        )


@dataclass(frozen=True)
class AppConfig:
    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    mcp: McpConfig = field(default_factory=McpConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    api_host: str = "0.0.0.0"
    api_port: int = 8400
    auto_respond: bool = False
    evidence_backend: str = "mcp"
    guided_pivots: bool = False


def load_config() -> AppConfig:
    return AppConfig(
        splunk=SplunkConfig.from_env(),
        mcp=McpConfig.from_env(),
        model=ModelConfig.from_env(),
        api_host=os.getenv("VERITRACE_API_HOST", "0.0.0.0"),
        api_port=int(os.getenv("VERITRACE_API_PORT", "8400")),
        auto_respond=_b("VERITRACE_AUTO_RESPOND", False),
        # mcp (default) | direct | fixture. fixture needs no Splunk or MCP (offline demo).
        evidence_backend=os.getenv("VERITRACE_EVIDENCE_BACKEND", "mcp"),
        # When true, the agent runs the proven investigation pivots so the small
        # local model never has to author SPL, and the model is used for what it
        # is good at: interpreting each real result, mapping MITRE and judging.
        guided_pivots=_b("VERITRACE_GUIDED_PIVOTS", False),
    )

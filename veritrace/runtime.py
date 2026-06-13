"""Wires the configured pieces into a ready-to-run Agent."""

from __future__ import annotations

from typing import Callable, Optional

from .agent import Agent
from .config import AppConfig, load_config
from .evidence import DirectSplunkEvidenceSource, EvidenceSource, McpEvidenceSource
from .ledger import LedgerWriter
from .mcp_client import McpClient
from .models import build_provider
from .splunk_io import HecWriter


def build_agent(
    cfg: Optional[AppConfig] = None,
    evidence: Optional[EvidenceSource] = None,
    on_event: Optional[Callable[[str, dict], None]] = None,
    evidence_backend: Optional[str] = None,
) -> Agent:
    cfg = cfg or load_config()
    backend = evidence_backend or cfg.evidence_backend

    splunk_service = None
    if cfg.model.provider == "splunk_hosted" or backend == "direct":
        from .splunk_io import connect

        splunk_service = connect(cfg.splunk)

    provider = build_provider(cfg.model, splunk_service=splunk_service)

    if evidence is None:
        if backend == "fixture":
            from .evidence import FakeEvidenceSource
            from .fixtures import scenario_fixtures

            evidence = FakeEvidenceSource(scenario_fixtures())
        elif backend == "direct":
            evidence = DirectSplunkEvidenceSource(splunk_service)
        else:
            evidence = McpEvidenceSource(McpClient(cfg.mcp.url))

    # In fixture mode there is no Splunk to write to, so the ledger streams to
    # the console callback only. Every other mode writes the ledger over HEC.
    hec = None if backend == "fixture" else HecWriter(cfg.splunk)
    ledger = LedgerWriter(cfg.splunk, hec=hec, on_event=on_event)
    return Agent(provider=provider, evidence=evidence, ledger=ledger, cfg=cfg)

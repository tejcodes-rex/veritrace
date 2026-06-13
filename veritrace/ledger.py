"""The reasoning ledger.

Every step the agent takes is written back into Splunk as a structured event, so
the investigation becomes operational data you can search, audit and replay long
after it ran. This is the mechanism that turns an opaque agent into a glass box:
the evidence, the reasoning, the confidence and the actions all live in Splunk
next to the telemetry they were drawn from.

If Splunk is unreachable (for example in an offline unit test) the ledger keeps
an in-memory copy and degrades quietly, so the agent never fails because it
could not write a log line.
"""

from __future__ import annotations

from typing import Callable, Optional

from . import chain
from .config import SplunkConfig
from .schemas import DetectionRule, Investigation, Step
from .splunk_io import HecWriter

SOURCETYPE_STEP = "veritrace:reasoning"
SOURCETYPE_INVESTIGATION = "veritrace:investigation"
SOURCETYPE_DETECTION = "veritrace:detection"


class LedgerWriter:
    def __init__(
        self,
        cfg: SplunkConfig,
        hec: Optional[HecWriter] = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
    ):
        self.cfg = cfg
        self.hec = hec
        self.on_event = on_event
        self.degraded = False
        # head of the tamper-evident hash chain, per investigation
        self._chain_head: dict[str, str] = {}

    def _emit(self, kind: str, payload: dict) -> None:
        if self.on_event:
            try:
                self.on_event(kind, payload)
            except Exception:  # noqa: BLE001 - never let a UI callback break the run
                pass

    def _send(self, event: dict, index: str, sourcetype: str) -> None:
        # Once a write fails, stop trying for the rest of the investigation so a
        # missing or unreachable Splunk does not add latency to every step.
        if not self.hec or self.degraded:
            return
        try:
            self.hec.send(event, index=index, sourcetype=sourcetype)
        except Exception:  # noqa: BLE001 - degrade quietly, keep investigating
            self.degraded = True

    def record_step(self, investigation_id: str, step: Step) -> None:
        # Seal the step into the tamper-evident chain before it is written or
        # streamed, so the console and Splunk both carry the same hashes.
        prev = self._chain_head.get(investigation_id) or chain.genesis(investigation_id)
        step.prev_hash = prev
        step.entry_hash = chain.digest(prev, step.model_dump(mode="json"))
        self._chain_head[investigation_id] = step.entry_hash
        event = {"investigation_id": investigation_id, **step.model_dump(mode="json")}
        self._send(event, self.cfg.index_ledger, SOURCETYPE_STEP)
        self._emit("step", event)

    def chain_root(self, investigation_id: str) -> str:
        """The current head of the chain, which seals the whole investigation."""
        return self._chain_head.get(investigation_id, "")

    def record_investigation(self, inv: Investigation) -> None:
        event = {
            "investigation_id": inv.investigation_id,
            "alert_id": inv.alert.alert_id,
            "alert_name": inv.alert.name,
            "status": inv.status,
            "verdict": inv.verdict.value if inv.verdict else None,
            "severity": inv.severity.value if inv.severity else None,
            "confidence": inv.confidence,
            "summary": inv.summary,
            "attack_chain": [s.model_dump(mode="json") for s in inv.attack_chain],
            "response_actions": [a.model_dump(mode="json") for a in inv.response_actions],
            "model_provider": inv.model_provider,
            "model_name": inv.model_name,
            "total_tokens": inv.total_tokens,
            "total_latency_ms": inv.total_latency_ms,
            "mttr_seconds": inv.mttr_seconds,
            "step_count": len(inv.steps),
            "ledger_root": inv.ledger_root or self.chain_root(inv.investigation_id),
        }
        self._send(event, self.cfg.index_ledger, SOURCETYPE_INVESTIGATION)
        self._emit("investigation", event)

    def record_detection(self, investigation_id: str, detection: DetectionRule) -> None:
        event = {"investigation_id": investigation_id, **detection.model_dump(mode="json")}
        self._send(event, self.cfg.index_detections, SOURCETYPE_DETECTION)
        self._emit("detection", event)

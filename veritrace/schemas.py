"""Data contracts shared across the agent, the ledger and the API.

These models are intentionally explicit. Every claim the agent makes carries a
pointer back to the Splunk evidence that supports it, which is what lets a human
verify the investigation rather than trust it blindly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StepKind(str, Enum):
    triage = "triage"
    plan = "plan"
    search = "search"
    observation = "observation"
    reasoning = "reasoning"
    correlation = "correlation"
    verdict = "verdict"
    detection = "detection"
    response_plan = "response_plan"
    error = "error"


class Verdict(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    benign = "benign"
    escalate = "escalate"
    inconclusive = "inconclusive"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class EvidenceRef(BaseModel):
    """A pointer to the raw Splunk events that back a claim."""

    label: str
    index: str
    sourcetype: str = ""
    spl: str
    result_count: int = 0
    sample: list[dict[str, Any]] = Field(default_factory=list)
    earliest: str = ""
    latest: str = ""


class AttackStage(BaseModel):
    order: int
    tactic: str
    technique_id: str
    technique_name: str
    narrative: str
    confidence: float = 0.0
    evidence_labels: list[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    action: str
    target: str
    rationale: str
    reversible: bool = True
    requires_approval: bool = True
    status: str = "proposed"  # proposed | approved | rejected | executed


class DetectionRule(BaseModel):
    name: str
    description: str
    spl: str
    rationale: str
    severity: Severity = Severity.high
    mitre_techniques: list[str] = Field(default_factory=list)
    schedule_cron: str = "*/5 * * * *"
    # populated after the agent backtests the rule against historical data
    backtest_hits_incident: Optional[int] = None
    backtest_false_positives: Optional[int] = None
    savedsearch_stanza: str = ""


class Step(BaseModel):
    seq: int
    kind: StepKind
    title: str
    detail: str = ""
    spl: str = ""
    tool: str = ""
    result_count: Optional[int] = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""
    model_reasoning: str = ""
    confidence: Optional[float] = None
    latency_ms: Optional[int] = None
    tokens_prompt: Optional[int] = None
    tokens_completion: Optional[int] = None
    ts: str = Field(default_factory=now_iso)
    # tamper-evident hash chain (set by the ledger as the step is sealed)
    prev_hash: str = ""
    entry_hash: str = ""


class Alert(BaseModel):
    alert_id: str
    name: str
    description: str = ""
    severity: Severity = Severity.medium
    entity: str = ""
    src: str = ""
    dest: str = ""
    user: str = ""
    raw_spl: str = ""
    fired_at: str = Field(default_factory=now_iso)
    index: str = "security"


class Investigation(BaseModel):
    investigation_id: str
    alert: Alert
    status: str = "running"  # running | completed | failed
    started_at: str = Field(default_factory=now_iso)
    completed_at: str = ""
    steps: list[Step] = Field(default_factory=list)
    attack_chain: list[AttackStage] = Field(default_factory=list)
    verdict: Optional[Verdict] = None
    severity: Optional[Severity] = None
    confidence: float = 0.0
    summary: str = ""
    response_actions: list[ResponseAction] = Field(default_factory=list)
    detection: Optional[DetectionRule] = None
    model_provider: str = ""
    model_name: str = ""
    total_tokens: int = 0
    total_latency_ms: int = 0
    mttr_seconds: float = 0.0
    # the final hash of the tamper-evident ledger chain, which seals the case
    ledger_root: str = ""

    def next_seq(self) -> int:
        return len(self.steps) + 1

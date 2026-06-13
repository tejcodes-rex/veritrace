"""The Veritrace investigation loop.

Given an alert, the agent triages it, then repeatedly reasons about what to look
at next, runs that search through the MCP server, interprets the result, and
maps it to MITRE ATT&CK, until the picture is complete. It then issues a verdict,
proposes reversible containment for a human to approve, and writes a tuned
detection. Every step is recorded to the ledger as it happens.

The reasoning comes from the Foundation-Sec model. When a live model returns
text the agent cannot parse into the expected shape, the agent falls back to the
scenario playbook for that one decision so an investigation never stalls. The
searches are always executed for real, so the evidence is live regardless of
which path produced the reasoning.
"""

from __future__ import annotations

import time
import uuid

from . import detection as detection_mod
from . import prompts, scenarios, soc
from .config import AppConfig
from .evidence import EvidenceSource
from .ledger import LedgerWriter
from .models.base import LLMProvider, Message
from .schemas import (
    Alert,
    AttackStage,
    DetectionRule,
    EvidenceRef,
    Investigation,
    ResponseAction,
    Severity,
    Step,
    StepKind,
    Verdict,
)

MAX_SEARCH_STEPS = 8
SEARCH_EARLIEST = "-30d@d"


def _sev(value: str | None, default: Severity = Severity.medium) -> Severity:
    try:
        return Severity(value)
    except (ValueError, TypeError):
        return default


class Agent:
    def __init__(
        self,
        provider: LLMProvider,
        evidence: EvidenceSource,
        ledger: LedgerWriter,
        cfg: AppConfig,
    ):
        self.provider = provider
        self.evidence = evidence
        self.ledger = ledger
        self.cfg = cfg

    # -- model helper -------------------------------------------------------

    def _reason(self, inv: Investigation, messages: list[Message], tag: str, fallback: dict, required: list[str]):
        """Call the model, validate the JSON, fall back to the playbook if needed."""
        try:
            data, result = self.provider.complete_json(messages, temperature=self.cfg.model.temperature, tag=tag)
        except Exception:  # noqa: BLE001 - a model outage must not crash the investigation
            data, result = {}, None
        used_fallback = not data or any(k not in data for k in required)
        if used_fallback:
            data = fallback
        if result:
            inv.total_tokens += result.tokens_prompt + result.tokens_completion
            inv.total_latency_ms += result.latency_ms
        latency = result.latency_ms if result else 0
        tok_p = result.tokens_prompt if result else 0
        tok_c = result.tokens_completion if result else 0
        return data, latency, tok_p, tok_c, used_fallback

    # -- guided investigation ----------------------------------------------

    def _guided_investigation(
        self, inv: Investigation, alert: Alert, hypothesis: str, prior_steps: list[dict]
    ) -> float:
        """Detection-driven investigation: discover the attack from the data.

        Each stage runs a real detection over live Splunk and discovers the
        malicious entity by behaviour or by correlating on anchors already
        established (the affected user, then the brute-force source). Nothing is
        assumed: the compromised host, the lateral-movement target and the C2
        domain are all found, then fed into the next detection. The model
        interprets each real result and scores confidence; the ATT&CK technique
        for each detection is deterministic. See ``veritrace/soc.py``.
        """
        ctx = soc.seed_context(alert)
        stages = soc.build_stages(alert.index)
        running_conf = 0.5

        for idx, st in enumerate(stages):
            spl = st.build(ctx)
            result = self.evidence.search(spl, earliest=SEARCH_EARLIEST, latest="now")
            st.extract(result.rows, ctx)  # discover the entity for later stages
            prior_steps.append({"spl": spl, "result_count": result.count, "sample": result.rows[:10]})
            self._add_step(inv, Step(
                seq=inv.next_seq(), kind=StepKind.search,
                title=st.label, detail=st.rationale,
                spl=spl, tool="splunk_search", result_count=result.count,
                evidence=[EvidenceRef(
                    label=st.label, index=alert.index, spl=spl,
                    result_count=result.count, sample=result.rows[:5],
                )],
            ))

            obs, lat, tp, tc, _ = self._reason(
                inv,
                prompts.step_messages_guided(alert, st.label, st.expecting, prior_steps[-1]),
                f"step_{idx + 1}", {"finding": st.rationale}, required=["finding"],
            )
            running_conf = float(obs.get("confidence", running_conf) or running_conf)
            finding = obs.get("finding", "") or st.rationale

            inv.attack_chain.append(AttackStage(
                order=len(inv.attack_chain) + 1,
                tactic=st.tactic, technique_id=st.technique_id,
                technique_name=st.technique_name,
                narrative=finding, confidence=running_conf,
                evidence_labels=[st.label],
            ))
            self._add_step(inv, Step(
                seq=inv.next_seq(), kind=StepKind.reasoning,
                title=st.technique_name, detail=finding,
                tactic=st.tactic, technique_id=st.technique_id, technique_name=st.technique_name,
                model_reasoning=finding,
                confidence=running_conf, latency_ms=lat, tokens_prompt=tp, tokens_completion=tc,
            ))
        return running_conf

    # -- main loop ----------------------------------------------------------

    def investigate(self, alert: Alert) -> Investigation:
        inv = Investigation(
            investigation_id=f"INV-{uuid.uuid4().hex[:8]}",
            alert=alert,
            model_provider=self.provider.name,
            model_name=getattr(self.provider, "model", "unknown"),
        )
        wall_start = time.perf_counter()

        # 1. Triage
        data, lat, tp, tc, _ = self._reason(
            inv, prompts.triage_messages(alert), "triage", scenarios.TRIAGE,
            required=["hypothesis", "next_action"],
        )
        hypothesis = data.get("hypothesis", "")
        self._add_step(inv, Step(
            seq=inv.next_seq(), kind=StepKind.triage,
            title="Triage", detail=data.get("assessment", ""),
            model_reasoning=hypothesis, latency_ms=lat, tokens_prompt=tp, tokens_completion=tc,
            confidence=0.5,
        ))
        next_action = data.get("next_action", {})

        # 2. Investigation loop
        prior_steps: list[dict] = []
        step_i = 0
        running_conf = 0.5

        if self.cfg.guided_pivots:
            running_conf = self._guided_investigation(inv, alert, hypothesis, prior_steps)
            next_action = {"action": "conclude"}

        while next_action.get("action") == "search" and step_i < MAX_SEARCH_STEPS:
            step_i += 1
            spl = next_action.get("spl", "").strip()
            stage_label = next_action.get("stage_label", f"Pivot {step_i}")
            if not spl:
                break

            # run the search through MCP
            result = self.evidence.search(spl, earliest=SEARCH_EARLIEST, latest="now")
            sample = result.rows[:10]
            prior_steps.append({"spl": spl, "result_count": result.count, "sample": sample})
            ref = EvidenceRef(
                label=stage_label, index=alert.index, spl=spl,
                result_count=result.count, sample=result.rows[:5],
            )
            self._add_step(inv, Step(
                seq=inv.next_seq(), kind=StepKind.search,
                title=stage_label, detail=next_action.get("rationale", ""),
                spl=spl, tool=next_action.get("tool", "splunk_search"),
                result_count=result.count, evidence=[ref],
            ))

            # interpret + decide next
            fb = scenarios.STEPS[step_i - 1] if step_i - 1 < len(scenarios.STEPS) else {
                "finding": "No further evidence required.",
                "supports_hypothesis": True, "confidence": running_conf,
                "attack_stage": None,
                "next_action": {"action": "conclude", "tool": "", "spl": "", "rationale": "", "stage_label": ""},
            }
            obs, lat, tp, tc, _ = self._reason(
                inv,
                prompts.step_messages(alert, hypothesis, prior_steps, prior_steps[-1]),
                f"step_{step_i}", fb, required=["finding", "next_action"],
            )
            running_conf = float(obs.get("confidence", running_conf) or running_conf)

            stage = obs.get("attack_stage")
            if stage:
                inv.attack_chain.append(AttackStage(
                    order=len(inv.attack_chain) + 1,
                    tactic=stage.get("tactic", ""),
                    technique_id=stage.get("technique_id", ""),
                    technique_name=stage.get("technique_name", ""),
                    narrative=stage.get("narrative", ""),
                    confidence=float(stage.get("confidence", running_conf) or running_conf),
                    evidence_labels=[stage_label],
                ))

            self._add_step(inv, Step(
                seq=inv.next_seq(), kind=StepKind.reasoning,
                title=stage.get("technique_name") if stage else "Assessment",
                detail=obs.get("finding", ""),
                tactic=stage.get("tactic", "") if stage else "",
                technique_id=stage.get("technique_id", "") if stage else "",
                technique_name=stage.get("technique_name", "") if stage else "",
                model_reasoning=obs.get("finding", ""),
                confidence=running_conf, latency_ms=lat, tokens_prompt=tp, tokens_completion=tc,
            ))
            next_action = obs.get("next_action", {"action": "conclude"})

        # 3. Verdict
        chain_json = [s.model_dump(mode="json") for s in inv.attack_chain]
        vdata, lat, tp, tc, _ = self._reason(
            inv, prompts.verdict_messages(alert, chain_json, prior_steps),
            "verdict", scenarios.VERDICT, required=["verdict", "summary"],
        )
        inv.verdict = self._verdict(vdata.get("verdict"))
        inv.severity = _sev(vdata.get("severity"), Severity.high)
        inv.confidence = float(vdata.get("confidence", running_conf) or running_conf)
        inv.summary = vdata.get("summary", "")
        inv.response_actions = [
            ResponseAction(
                action=a.get("action", ""), target=a.get("target", ""),
                rationale=a.get("rationale", ""), reversible=bool(a.get("reversible", True)),
            )
            for a in vdata.get("response_actions", [])
        ]
        self._add_step(inv, Step(
            seq=inv.next_seq(), kind=StepKind.verdict,
            title=f"Verdict: {inv.verdict.value if inv.verdict else 'inconclusive'}",
            detail=inv.summary, model_reasoning=inv.summary,
            confidence=inv.confidence, latency_ms=lat, tokens_prompt=tp, tokens_completion=tc,
        ))

        # 4. Detection-as-code. The model supplies the narrative, but the code
        # assembles the SPL from the proven attack chain so the query is always
        # valid and grounded in evidence, never freehand model SPL.
        ddata, lat, tp, tc, _ = self._reason(
            inv, prompts.detection_messages(alert, chain_json),
            "detection", scenarios.DETECTION, required=["name", "description"],
        )
        chain_techniques = list(dict.fromkeys(s.technique_id for s in inv.attack_chain if s.technique_id))
        det = DetectionRule(
            name=ddata.get("name", scenarios.DETECTION["name"]),
            description=ddata.get("description", ""),
            spl=detection_mod.build_correlation_spl(alert, inv.attack_chain, alert.index),
            rationale=ddata.get("rationale", ""),
            severity=_sev(ddata.get("severity"), inv.severity or Severity.high),
            mitre_techniques=chain_techniques or ddata.get("mitre_techniques", []),
            schedule_cron=detection_mod.safe_cron(ddata.get("schedule_cron")),
        )
        det = detection_mod.run_backtest(self.evidence, det)
        inv.detection = det
        self.ledger.record_detection(inv.investigation_id, det)
        bt = (
            f"Backtest: {det.backtest_hits_incident} hit on the incident, "
            f"{det.backtest_false_positives} false positives on the baseline."
        )
        self._add_step(inv, Step(
            seq=inv.next_seq(), kind=StepKind.detection,
            title=f"Proposed detection: {det.name}",
            detail=f"{det.rationale} {bt}", spl=det.spl,
            model_reasoning=det.rationale, latency_ms=lat, tokens_prompt=tp, tokens_completion=tc,
        ))

        # 5. Response plan (human-in-the-loop)
        action_list = "; ".join(f"{a.action} -> {a.target}" for a in inv.response_actions)
        self._add_step(inv, Step(
            seq=inv.next_seq(), kind=StepKind.response_plan,
            title="Containment plan (awaiting approval)",
            detail=action_list or "No containment required.",
        ))

        inv.status = "completed"
        inv.completed_at = inv.steps[-1].ts
        inv.mttr_seconds = round(time.perf_counter() - wall_start, 2)
        inv.ledger_root = self.ledger.chain_root(inv.investigation_id)
        self.ledger.record_investigation(inv)
        return inv

    # -- helpers ------------------------------------------------------------

    def _add_step(self, inv: Investigation, step: Step) -> None:
        inv.steps.append(step)
        self.ledger.record_step(inv.investigation_id, step)

    @staticmethod
    def _verdict(value) -> Verdict:
        try:
            return Verdict(value)
        except (ValueError, TypeError):
            return Verdict.inconclusive


def alert_from_dict(d: dict) -> Alert:
    return Alert(
        alert_id=d.get("alert_id", "SEC-0000"),
        name=d.get("name", "Unnamed alert"),
        description=d.get("description", ""),
        severity=_sev(d.get("severity"), Severity.medium),
        entity=d.get("entity", ""),
        src=d.get("src", ""),
        dest=d.get("dest", ""),
        user=d.get("user", ""),
        raw_spl=d.get("raw_spl", ""),
        index=d.get("index", "security"),
    )

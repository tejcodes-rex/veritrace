"""End-to-end investigation with no Splunk and no GPU.

Uses the replay provider for reasoning and a fixture evidence source for search
results, so the full agent loop runs anywhere. This is the offline demo path and
the regression guard for the agent's control flow.
"""

from __future__ import annotations

from veritrace import scenarios
from veritrace.agent import Agent, alert_from_dict
from veritrace.config import load_config
from veritrace.evidence import FakeEvidenceSource
from veritrace.ledger import LedgerWriter
from veritrace.models.replay import ReplayProvider
from veritrace.schemas import Verdict


def _fixtures():
    return [
        ("stats count as hits", [{"hits": "1"}]),
        (f'dest_ip="{scenarios.ATTACKER_IP}"', [{"dest_ip": scenarios.ATTACKER_IP, "bytes_out": "4812553216"}]),
        ("dest_port=445", [{"dest_ip": scenarios.HOST_DB_IP, "dest": scenarios.HOST_DB, "bytes": "918273"}]),
        ("sourcetype=Sysmon", [{"dest": scenarios.HOST_ENTRY, "parent_process_name": "explorer.exe",
                                 "process_name": "powershell.exe", "CommandLine": "powershell -enc SQBFAFgA"}]),
        ("sourcetype=stream:dns", [{"_time": "1", "count": "1"} for _ in range(5)]),
        ("action=success", [{"src": scenarios.ATTACKER_IP, "first_seen": "now", "count": "1"},
                            {"src": scenarios.CORP_IP, "first_seen": "old", "count": "200"}]),
        ("stats count by action", [{"action": "failure", "src": scenarios.ATTACKER_IP, "count": "43"},
                                   {"action": "success", "src": scenarios.ATTACKER_IP, "count": "1"}]),
    ]


def build_offline_agent(events=None):
    cfg = load_config()
    on_event = (lambda kind, payload: events.append((kind, payload))) if events is not None else None
    ledger = LedgerWriter(cfg.splunk, hec=None, on_event=on_event)
    return Agent(
        provider=ReplayProvider(),
        evidence=FakeEvidenceSource(_fixtures()),
        ledger=ledger,
        cfg=cfg,
    )


def test_full_investigation_completes():
    agent = build_offline_agent()
    inv = agent.investigate(alert_from_dict(scenarios.ALERT))

    assert inv.status == "completed"
    assert inv.verdict == Verdict.true_positive
    assert inv.confidence >= 0.9
    # six kill-chain stages from brute force through exfiltration
    assert len(inv.attack_chain) == 6
    technique_ids = [s.technique_id for s in inv.attack_chain]
    assert technique_ids == ["T1110.001", "T1078", "T1059.001", "T1021.002", "T1071.004", "T1041"]
    # the agent proposes and backtests a detection
    assert inv.detection is not None
    assert inv.detection.backtest_hits_incident == 1
    assert inv.detection.backtest_false_positives == 0
    assert inv.detection.savedsearch_stanza.startswith("[")
    # reversible containment, proposed for human approval
    assert len(inv.response_actions) == 5
    assert all(a.status == "proposed" for a in inv.response_actions)


def test_live_event_stream_emitted():
    events: list = []
    agent = build_offline_agent(events)
    agent.investigate(alert_from_dict(scenarios.ALERT))
    kinds = [k for k, _ in events]
    assert "step" in kinds
    assert "investigation" in kinds
    assert "detection" in kinds


def test_ledger_chain_is_tamper_evident():
    from veritrace import chain

    agent = build_offline_agent()
    inv = agent.investigate(alert_from_dict(scenarios.ALERT))
    steps = [s.model_dump(mode="json") for s in inv.steps]

    # every step is sealed and the case carries a ledger root
    assert inv.ledger_root
    assert all(s["entry_hash"] and s["prev_hash"] for s in steps)

    # an untouched chain verifies against its sealed root
    ok = chain.verify(inv.investigation_id, steps, inv.ledger_root)
    assert ok["ok"] is True
    assert ok["broken_at"] is None
    assert ok["computed_root"] == inv.ledger_root

    # altering any sealed step is detected at that step
    steps[3]["detail"] += " (tampered)"
    bad = chain.verify(inv.investigation_id, steps, inv.ledger_root)
    assert bad["ok"] is False
    assert bad["broken_at"] == steps[3]["seq"]


def test_detection_spl_is_valid_and_grounded():
    agent = build_offline_agent()
    inv = agent.investigate(alert_from_dict(scenarios.ALERT))
    spl = inv.detection.spl

    # the SPL is code-built, valid, and grounded in the confirmed entities
    assert spl.startswith("index=")
    assert "| stats" in spl
    assert scenarios.VICTIM_USER in spl
    assert scenarios.ATTACKER_IP in spl
    # the techniques come from the proven chain, not freehand model output
    assert "T1021.002" in inv.detection.mitre_techniques
    assert "T1041" in inv.detection.mitre_techniques

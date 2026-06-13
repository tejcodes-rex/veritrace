"""Prompt construction for the Foundation-Sec reasoning model.

Foundation-Sec is an 8B cybersecurity model, so the prompts are tight and ask
for a single strict JSON object. The contracts here match what agent.py parses
and what the replay provider records, so a live run and an offline run shape the
investigation the same way.
"""

from __future__ import annotations

import json

from .models.base import Message
from .schemas import Alert

SYSTEM = (
    "You are Veritrace, an autonomous Tier-1 SOC analyst working inside a Splunk "
    "environment. You investigate alerts by running read-only SPL searches through "
    "MCP tools and reasoning about the security telemetry they return. You map "
    "findings to MITRE ATT&CK. You are precise, you cite the evidence you saw, and "
    "you never invent data. Respond with exactly one JSON object and no other text."
)

TOOLS_HINT = (
    "Available MCP tool: splunk_search(spl, earliest, latest). Useful sourcetypes in "
    "index=security: linux_secure (authentication: user, src, action), Sysmon "
    "(endpoint: dest, user, parent_process_name, process_name, CommandLine), "
    "stream:tcp (network: src_ip, dest_ip, dest_port, bytes, bytes_out), stream:dns "
    "(dns: src_ip, query)."
)


def _evidence_log(steps: list[dict]) -> str:
    if not steps:
        return "No searches run yet."
    lines = []
    for s in steps:
        lines.append(
            f"- ran: {s['spl']}\n  result_count={s['result_count']}; "
            f"sample={json.dumps(s['sample'][:3])}"
        )
    return "\n".join(lines)


def triage_messages(alert: Alert) -> list[Message]:
    user = (
        f"{TOOLS_HINT}\n\n"
        f"A Splunk alert fired:\n"
        f"  name: {alert.name}\n  description: {alert.description}\n"
        f"  severity: {alert.severity.value}\n  user: {alert.user}\n"
        f"  source: {alert.src}\n  destination: {alert.dest}\n\n"
        "Triage it. Return JSON with keys: assessment (string), hypothesis (string), "
        "severity (critical|high|medium|low), next_action (object with action='search', "
        "tool='splunk_search', spl (string), rationale (string), expecting (string), "
        "stage_label (short string)). The spl must be a valid read-only SPL query."
    )
    return [Message("system", SYSTEM), Message("user", user)]


def step_messages(alert: Alert, hypothesis: str, prior_steps: list[dict], last_result: dict) -> list[Message]:
    user = (
        f"{TOOLS_HINT}\n\n"
        f"Investigation of alert '{alert.name}'. Working hypothesis: {hypothesis}\n\n"
        f"Searches so far:\n{_evidence_log(prior_steps)}\n\n"
        f"Most recent search returned {last_result['result_count']} rows. Sample:\n"
        f"{json.dumps(last_result['sample'][:5])}\n\n"
        "Interpret this result, then decide the next move. If the result shows "
        "adversary behaviour, you must map it to one MITRE ATT&CK technique in "
        "attack_stage (do not leave it null when the rows show malicious activity). "
        "Return JSON with keys: finding (string, what the result shows), "
        "supports_hypothesis (bool), confidence (0..1 as a number), attack_stage "
        "(object with tactic, technique_id like 'T1021.002', technique_name, "
        "narrative, confidence; null only if the rows are benign), next_action "
        "(object with action='search' or 'conclude', tool, spl, rationale, expecting, "
        "stage_label). Choose action='conclude' once you have followed the chain "
        "through exfiltration or have no stronger pivot left."
    )
    return [Message("system", SYSTEM), Message("user", user)]


def step_messages_guided(
    alert: Alert, stage_label: str, expecting: str, last_result: dict
) -> list[Message]:
    """Focused interpretation prompt for guided mode.

    The agent has already run the right search for this stage, so the model is
    asked to interpret only this concrete result and classify the one technique
    it demonstrates, rather than carry forward the opening hypothesis. This stops
    a small model from re-labelling every later stage as the initial brute force.
    """
    user = (
        f"You are investigating the alert '{alert.name}'.\n"
        f"This step ran a Splunk search to: {stage_label}.\n"
        f"What that search looks for: {expecting}\n\n"
        f"The search returned {last_result['result_count']} rows. Sample rows:\n"
        f"{json.dumps(last_result['sample'][:6])}\n\n"
        "Interpret THIS specific result on its own. In one or two sentences, state "
        "what these rows show, citing the concrete values (hosts, IP addresses, "
        "counts, byte volumes, commands, domains). Then map it to the single MITRE "
        "ATT&CK technique this evidence most directly demonstrates. Do not default to "
        "the alert's initial brute-force framing if the rows show a later stage such "
        "as execution, lateral movement, command-and-control, or exfiltration.\n\n"
        "Return one JSON object with keys: finding (string), supports_hypothesis "
        "(bool), confidence (0..1 number), attack_stage (object with tactic, "
        "technique_id like 'T1021.002', technique_name, narrative, confidence)."
    )
    return [Message("system", SYSTEM), Message("user", user)]


def verdict_messages(alert: Alert, attack_chain: list[dict], prior_steps: list[dict]) -> list[Message]:
    user = (
        f"Investigation of alert '{alert.name}' is complete.\n\n"
        f"Attack chain assembled:\n{json.dumps(attack_chain, indent=2)}\n\n"
        f"Evidence gathered across {len(prior_steps)} searches.\n\n"
        "Deliver the verdict. Return JSON with keys: verdict "
        "(true_positive|false_positive|benign|escalate|inconclusive), severity "
        "(critical|high|medium|low|info), confidence (0..1), summary (string, a tight "
        "incident summary an analyst can paste into a ticket), response_actions (array "
        "of objects with action, target, rationale, reversible bool). Response actions "
        "are proposals for a human to approve, so prefer reversible containment."
    )
    return [Message("system", SYSTEM), Message("user", user)]


def detection_messages(alert: Alert, attack_chain: list[dict]) -> list[Message]:
    user = (
        f"The original alert '{alert.name}' fired on a single signal and is noisy on its "
        "own. Using the confirmed attack chain below, design one higher-fidelity "
        "correlation detection that fires only when the meaningful stages co-occur, which "
        "is what made this a real breach. Describe the detection; the platform compiles "
        "the SPL from the confirmed stages, so you do not write SPL.\n\n"
        f"Attack chain:\n{json.dumps(attack_chain, indent=2)}\n\n"
        "Return JSON with keys: name (string, a clear detection title), description "
        "(string, what condition fires it, in plain terms), rationale (why correlating "
        "these stages is higher fidelity than the original single-signal alert), severity "
        "(critical|high|medium|low), schedule_cron (a standard 5-field cron string)."
    )
    return [Message("system", SYSTEM), Message("user", user)]

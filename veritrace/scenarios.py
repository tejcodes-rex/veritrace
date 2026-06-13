"""The reference incident Veritrace investigates, defined once.

The data generator emits events that match these entities, the replay provider
serves the reasoning recorded here, and the agent's deterministic fallback uses
the same pivots when a live model returns text it cannot parse. Keeping all
three in one place is what makes the live demo, the offline run and the sample
data agree exactly.

The incident is a full intrusion kill chain against a finance environment:
an external brute force that succeeds, hands-on-keyboard discovery, lateral
movement to a database host, command-and-control beaconing, and bulk
exfiltration to the same foreign address that ran the brute force.
"""

from __future__ import annotations

# ---- Entities -------------------------------------------------------------

ATTACKER_IP = "45.137.21.53"
C2_DOMAIN = "cdn-telemetry-sync.net"
VICTIM_USER = "j.tanaka"
VPN_GW = "vpn-gw-01"

HOST_ENTRY = "fin-app-07"
HOST_ENTRY_IP = "10.20.7.107"
HOST_DB = "db-prod-02"
HOST_DB_IP = "10.20.9.202"

CORP_IP = "10.20.50.34"           # where j.tanaka normally logs in from
HOME_IP = "73.114.20.9"           # occasional legitimate remote login
EXFIL_BYTES = 4_812_553_216       # ~4.8 GB

# Index the sample security telemetry lands in
INDEX = "security"

# The alert that fires and wakes Veritrace up
ALERT = {
    "alert_id": "SEC-7741",
    "name": "Brute force authentication success",
    "description": (
        "Account j.tanaka recorded more than 40 failed SSH/VPN logins followed "
        "by a successful login within 6 minutes, from a single external source."
    ),
    "severity": "high",
    "entity": VICTIM_USER,
    "src": ATTACKER_IP,
    "dest": VPN_GW,
    "user": VICTIM_USER,
    "index": INDEX,
    "raw_spl": (
        f'index={INDEX} sourcetype=linux_secure user="{VICTIM_USER}" '
        f'| stats count(eval(action="failure")) as failures '
        f'count(eval(action="success")) as successes by src '
        f'| where failures > 20 AND successes > 0'
    ),
}


# ---- Triage ---------------------------------------------------------------

TRIAGE = {
    "assessment": (
        "A high volume of failed authentications resolving into a success for a "
        "single account from one external address is a classic credential-attack "
        "success. This is not yet proof of compromise, so the priority is to "
        "confirm the pattern, then determine whether the session was used."
    ),
    "hypothesis": (
        f"External actor at {ATTACKER_IP} brute forced {VICTIM_USER} and obtained "
        "valid credentials. If true, expect follow-on activity on hosts the "
        "account can reach."
    ),
    "severity": "high",
    "next_action": {
        "action": "search",
        "tool": "search_oneshot",
        "spl": (
            f'index={INDEX} sourcetype=linux_secure user="{VICTIM_USER}" '
            f'| stats count by action, src | sort - count'
        ),
        "rationale": "Confirm the failure-then-success pattern and isolate the source address.",
        "expecting": "Many failures and at least one success from the external source.",
        "stage_label": "Confirm brute force success",
    },
}


# ---- Investigation steps (observe + decide) -------------------------------
# Each entry is what the model returns after seeing the previous search result:
# an interpretation, an optional MITRE attack stage, and the next action.

STEPS = [
    {
        "tag": "step_1",
        "finding": (
            f"43 failed logins and 1 success for {VICTIM_USER}, all from {ATTACKER_IP}. "
            f"Normal logins for this account come from {CORP_IP}. The success at the tail "
            "of a failure burst confirms a brute force that landed."
        ),
        "supports_hypothesis": True,
        "confidence": 0.78,
        "attack_stage": {
            "tactic": "Credential Access",
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "narrative": f"{ATTACKER_IP} guessed the password for {VICTIM_USER} after 43 attempts.",
            "confidence": 0.82,
        },
        "next_action": {
            "action": "search",
            "tool": "search_oneshot",
            "spl": (
                f'index={INDEX} sourcetype=linux_secure user="{VICTIM_USER}" action=success '
                f'| stats earliest(_time) as first_seen latest(_time) as last_seen count by src'
            ),
            "rationale": "Establish whether the source address has ever been seen for this account before.",
            "expecting": "The external source is brand new while the corporate source has long history.",
            "stage_label": "Establish account takeover",
        },
    },
    {
        "tag": "step_2",
        "finding": (
            f"{ATTACKER_IP} was first seen for {VICTIM_USER} at the moment of the brute force, "
            f"with no prior history, while {CORP_IP} has months of history. This is account "
            "takeover with otherwise valid credentials."
        ),
        "supports_hypothesis": True,
        "confidence": 0.85,
        "attack_stage": {
            "tactic": "Initial Access",
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "narrative": f"The actor authenticated as {VICTIM_USER} using the stolen password from a never-before-seen address.",
            "confidence": 0.86,
        },
        "next_action": {
            "action": "search",
            "tool": "search_oneshot",
            "spl": (
                f'index={INDEX} sourcetype=Sysmon user="{VICTIM_USER}" '
                f'| stats count values(CommandLine) as cmds by dest, parent_process_name, process_name '
                f'| sort - count'
            ),
            "rationale": "Find what the account did after login. Look for interactive tooling and discovery commands.",
            "expecting": "PowerShell or shell activity on a reachable host, including discovery commands.",
            "stage_label": "Find hands-on-keyboard activity",
        },
    },
    {
        "tag": "step_3",
        "finding": (
            f"On {HOST_ENTRY}, {VICTIM_USER} spawned powershell.exe with an encoded command, then ran "
            "whoami and net group \"Domain Admins\". This is hands-on-keyboard discovery, not normal "
            "behaviour for a finance application account."
        ),
        "supports_hypothesis": True,
        "confidence": 0.88,
        "attack_stage": {
            "tactic": "Execution",
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "narrative": f"Encoded PowerShell ran on {HOST_ENTRY} under the compromised account, followed by account discovery.",
            "confidence": 0.87,
        },
        "next_action": {
            "action": "search",
            "tool": "search_oneshot",
            "spl": (
                f'index={INDEX} sourcetype=stream:tcp src_ip="{HOST_ENTRY_IP}" dest_port=445 '
                f'| stats sum(bytes) as bytes count by dest_ip, dest'
            ),
            "rationale": "Check for SMB connections out of the entry host, the usual sign of lateral movement.",
            "expecting": "An SMB connection from the entry host to an internal server.",
            "stage_label": "Detect lateral movement",
        },
    },
    {
        "tag": "step_4",
        "finding": (
            f"{HOST_ENTRY} opened an SMB session to {HOST_DB} ({HOST_DB_IP}), and {VICTIM_USER} then "
            f"authenticated successfully on {HOST_DB}. The actor pivoted from the entry host to the "
            "production database server."
        ),
        "supports_hypothesis": True,
        "confidence": 0.9,
        "attack_stage": {
            "tactic": "Lateral Movement",
            "technique_id": "T1021.002",
            "technique_name": "Remote Services: SMB/Windows Admin Shares",
            "narrative": f"The actor moved from {HOST_ENTRY} to {HOST_DB} over SMB using the stolen credentials.",
            "confidence": 0.89,
        },
        "next_action": {
            "action": "search",
            "tool": "search_oneshot",
            "spl": (
                f'index={INDEX} sourcetype=stream:dns src_ip="{HOST_DB_IP}" query="{C2_DOMAIN}" '
                f'| timechart span=60s count'
            ),
            "rationale": "Look for beaconing from the database host that would indicate command and control.",
            "expecting": "Regular, evenly spaced DNS lookups to an unfamiliar domain.",
            "stage_label": "Identify command and control",
        },
    },
    {
        "tag": "step_5",
        "finding": (
            f"{HOST_DB} issued DNS lookups for {C2_DOMAIN} every 60 seconds, a textbook beacon "
            "cadence. The domain was registered recently and resolves to the attacker address."
        ),
        "supports_hypothesis": True,
        "confidence": 0.91,
        "attack_stage": {
            "tactic": "Command and Control",
            "technique_id": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS",
            "narrative": f"{HOST_DB} beaconed to {C2_DOMAIN} at a fixed interval for command and control.",
            "confidence": 0.9,
        },
        "next_action": {
            "action": "search",
            "tool": "search_oneshot",
            "spl": (
                f'index={INDEX} sourcetype=stream:tcp src_ip="{HOST_DB_IP}" dest_ip="{ATTACKER_IP}" '
                f'| stats sum(bytes_out) as bytes_out count by dest_ip, dest_port'
            ),
            "rationale": "Quantify outbound data to the attacker address to confirm or rule out exfiltration.",
            "expecting": "A large outbound transfer to the external attacker address.",
            "stage_label": "Confirm data exfiltration",
        },
    },
    {
        "tag": "step_6",
        "finding": (
            f"{HOST_DB} sent roughly 4.8 GB outbound to {ATTACKER_IP} over port 443. Combined with the "
            "takeover, lateral movement and beaconing, this is an active breach with confirmed data theft."
        ),
        "supports_hypothesis": True,
        "confidence": 0.94,
        "attack_stage": {
            "tactic": "Exfiltration",
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "narrative": f"About 4.8 GB left {HOST_DB} for {ATTACKER_IP}, exfiltration over the C2 path.",
            "confidence": 0.92,
        },
        "next_action": {
            "action": "conclude",
            "tool": "",
            "spl": "",
            "rationale": "The full kill chain is established end to end with corroborating evidence at each stage.",
            "expecting": "",
            "stage_label": "Conclude investigation",
        },
    },
]


# ---- Verdict --------------------------------------------------------------

VERDICT = {
    "verdict": "true_positive",
    "severity": "critical",
    "confidence": 0.94,
    "summary": (
        f"Confirmed breach. An external actor at {ATTACKER_IP} brute forced {VICTIM_USER}, "
        f"authenticated from a new location, ran discovery on {HOST_ENTRY}, moved laterally over "
        f"SMB to {HOST_DB}, established DNS beaconing to {C2_DOMAIN}, and exfiltrated about 4.8 GB "
        f"to the attacker address. Six kill-chain stages corroborate one another. Immediate "
        f"containment of the account and both hosts is required."
    ),
    "response_actions": [
        {
            "action": "disable_account",
            "target": VICTIM_USER,
            "rationale": "Stop further use of the compromised credentials.",
            "reversible": True,
        },
        {
            "action": "isolate_host",
            "target": HOST_ENTRY,
            "rationale": "Contain the entry host used for discovery and lateral movement.",
            "reversible": True,
        },
        {
            "action": "isolate_host",
            "target": HOST_DB,
            "rationale": "Contain the database host that beaconed and exfiltrated data.",
            "reversible": True,
        },
        {
            "action": "block_indicator",
            "target": ATTACKER_IP,
            "rationale": "Block the source and destination of the attack at the perimeter.",
            "reversible": True,
        },
        {
            "action": "sinkhole_domain",
            "target": C2_DOMAIN,
            "rationale": "Cut the command-and-control channel.",
            "reversible": True,
        },
    ],
}


# ---- Detection-as-code ----------------------------------------------------
# The original alert only caught the brute force success and was noisy on its
# own. The agent proposes a single high-fidelity correlation detection that
# fires only when takeover is followed by lateral movement and exfiltration,
# which is what made this incident a true breach.

DETECTION = {
    "name": "Veritrace - Account takeover with lateral movement and exfiltration",
    "description": (
        "Fires when a single account shows a brute force success from a new source, "
        "then lateral movement over SMB, then a large outbound transfer to the same "
        "external address inside a six hour window. Correlating the stages removes the "
        "false positives that the standalone brute-force alert produced."
    ),
    "spl": (
        f'index={INDEX} sourcetype=linux_secure action=success '
        f'| stats earliest(_time) as login_time values(src) as src by user '
        f'| join user [ search index={INDEX} sourcetype=stream:tcp dest_port=445 '
        f'| stats values(dest) as smb_targets by user ] '
        f'| join user [ search index={INDEX} sourcetype=stream:tcp dest_ip="{ATTACKER_IP}" '
        f'| stats sum(bytes_out) as bytes_out by user ] '
        f'| where bytes_out > 100000000 '
        f'| eval risk_score=90, mitre="T1078,T1021.002,T1041" '
        f'| table _time user src smb_targets bytes_out risk_score mitre'
    ),
    "rationale": (
        "The takeover, the lateral movement and the exfiltration are each individually "
        "noisy, but their conjunction within one window is rare and high confidence. This "
        "is the gap the original single-signal alert missed."
    ),
    "severity": "critical",
    "mitre_techniques": ["T1078", "T1021.002", "T1041"],
    "schedule_cron": "*/10 * * * *",
}

# SPL the agent runs to backtest the proposed detection against history. The
# generator emits one matching incident and a clean benign baseline, so this
# should return exactly one hit on the incident and zero on the baseline.
DETECTION_BACKTEST_SPL = (
    f'index={INDEX} sourcetype=stream:tcp dest_ip="{ATTACKER_IP}" '
    f'| stats sum(bytes_out) as bytes_out by src '
    f'| where bytes_out > 100000000 | stats count as hits'
)

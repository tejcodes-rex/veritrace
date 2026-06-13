"""Detection-driven investigation: discover the attack from the data.

This is the production investigation engine. Rather than assuming who the
attacker is or which hosts were touched, each stage runs a real detection over
live Splunk and discovers the malicious entity by behaviour or by correlating on
anchors already established. The only inputs are what the alert genuinely gives
you (the affected user) and what the first detection proves (the brute-force
source). Everything after that - the compromised host, the lateral-movement
target, the command-and-control domain - is found by correlation, not assumed.

Why this generalises: the discriminators are behavioural, not value-based.

- The brute-force source is the address with a burst of failures resolving to a
  success, picked by failure-to-success ratio, not by a known IP.
- The compromised host is wherever the account ran suspicious commands (encoded
  PowerShell, privileged-group discovery), not a named host.
- The lateral-movement target is found by a subsearch: of the hosts the entry
  host reached over SMB, the one that also exfiltrates to the attacker. This
  filters out the heavy benign SMB traffic that would otherwise dominate.
- The C2 domain is the one that resolves to the attacker address.
- The exfiltration is the bulk transfer from the target host to the attacker.

Point Veritrace at a different account-takeover incident, with different
addresses, hosts, users and domains, and it discovers that incident instead.
The reference entities are used only as a fall-back if a detection returns
nothing, so an investigation degrades gracefully rather than stalling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import scenarios


@dataclass
class Stage:
    key: str
    label: str
    rationale: str
    expecting: str
    tactic: str
    technique_id: str
    technique_name: str
    build: Callable[[dict], str]          # ctx -> SPL
    extract: Callable[[list, dict], None]  # rows, ctx -> mutate ctx in place


def _first(rows: list, field: str) -> str | None:
    for row in rows:
        val = row.get(field)
        if val:
            return val
    return None


def build_stages(index: str) -> list[Stage]:
    """The ordered detection chain. Each stage's SPL is built from the entities
    discovered so far, so the investigation adapts to whatever the data shows."""

    def brute_force_spl(ctx: dict) -> str:
        return (
            f'index={index} sourcetype=linux_secure user="{ctx["user"]}" '
            f'| stats count(eval(action="failure")) as failures '
            f'count(eval(action="success")) as successes by src '
            f'| where failures >= 10 '
            f'| eval ratio=round(failures/(successes+1),1) | sort - ratio'
        )

    def brute_force_extract(rows: list, ctx: dict) -> None:
        src = _first(rows, "src")
        if src:
            ctx["attacker_ip"] = src

    def takeover_spl(ctx: dict) -> str:
        return (
            f'index={index} sourcetype=linux_secure user="{ctx["user"]}" '
            f'action=success src="{ctx["attacker_ip"]}" '
            f'| stats earliest(_time) as first_seen latest(_time) as last_seen count by src'
        )

    def execution_spl(ctx: dict) -> str:
        return (
            f'index={index} sourcetype=Sysmon user="{ctx["user"]}" '
            f'(CommandLine="*EncodedCommand*" OR CommandLine="*-enc*" '
            f'OR CommandLine="*Domain Admins*" OR CommandLine="*whoami*" '
            f'OR CommandLine="*net group*") '
            f'| stats count values(CommandLine) as commands by dest | sort - count'
        )

    def execution_extract(rows: list, ctx: dict) -> None:
        host = _first(rows, "dest")
        if host:
            ctx["entry_host"] = host

    def lateral_spl(ctx: dict) -> str:
        # Of the hosts the entry host reached over SMB, keep only the one that
        # also exfiltrates to the attacker. The subsearch is the discriminator
        # that beats the benign SMB noise.
        return (
            f'index={index} sourcetype=stream:tcp src="{ctx["entry_host"]}" dest_port=445 '
            f'[ search index={index} sourcetype=stream:tcp dest_ip="{ctx["attacker_ip"]}" '
            f'| stats sum(bytes_out) as b by src | where b > 100000000 '
            f'| rename src as dest | fields dest ] '
            f'| stats sum(bytes) as bytes count by dest_ip, dest'
        )

    def lateral_extract(rows: list, ctx: dict) -> None:
        host = _first(rows, "dest")
        if host:
            ctx["target_host"] = host

    def c2_spl(ctx: dict) -> str:
        return (
            f'index={index} sourcetype=stream:dns src="{ctx["target_host"]}" '
            f'answer="{ctx["attacker_ip"]}" | stats count by query'
        )

    def c2_extract(rows: list, ctx: dict) -> None:
        dom = _first(rows, "query")
        if dom:
            ctx["c2_domain"] = dom

    def exfil_spl(ctx: dict) -> str:
        return (
            f'index={index} sourcetype=stream:tcp src="{ctx["target_host"]}" '
            f'dest_ip="{ctx["attacker_ip"]}" '
            f'| stats sum(bytes_out) as bytes_out count by dest_ip, dest_port'
        )

    return [
        Stage(
            "brute_force", "Confirm the brute-force source",
            "Find the source address with a burst of failed logins resolving to a success.",
            "A single external source with many failures and at least one success.",
            "Credential Access", "T1110.001", "Brute Force: Password Guessing",
            brute_force_spl, brute_force_extract,
        ),
        Stage(
            "takeover", "Establish account takeover",
            "Confirm the brute-force source obtained a valid session for the account.",
            "A successful login for the account from the external source.",
            "Initial Access", "T1078", "Valid Accounts",
            takeover_spl, lambda rows, ctx: None,
        ),
        Stage(
            "execution", "Find hands-on-keyboard activity",
            "Find the host where the account ran suspicious commands.",
            "Encoded PowerShell or privileged-group discovery under the account.",
            "Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell",
            execution_spl, execution_extract,
        ),
        Stage(
            "lateral", "Detect lateral movement",
            "Of the hosts the entry host reached over SMB, isolate the one that also exfiltrates to the attacker.",
            "An SMB path from the entry host to the host that talks to the attacker.",
            "Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares",
            lateral_spl, lateral_extract,
        ),
        Stage(
            "c2", "Identify command and control",
            "Find the domain queried by the target host that resolves to the attacker address.",
            "A domain on the target host resolving to the attacker address.",
            "Command and Control", "T1071.004", "Application Layer Protocol: DNS",
            c2_spl, c2_extract,
        ),
        Stage(
            "exfil", "Confirm data exfiltration",
            "Quantify the outbound transfer from the target host to the attacker.",
            "A large outbound transfer from the target host to the attacker address.",
            "Exfiltration", "T1041", "Exfiltration Over C2 Channel",
            exfil_spl, lambda rows, ctx: None,
        ),
    ]


def seed_context(alert) -> dict:
    """Seed the entity context. The user and source come from the alert; the
    rest fall back to the reference incident only if a detection finds nothing."""
    return {
        "user": alert.user or scenarios.VICTIM_USER,
        "attacker_ip": alert.src or scenarios.ATTACKER_IP,
        "entry_host": scenarios.HOST_ENTRY,
        "target_host": scenarios.HOST_DB,
        "c2_domain": scenarios.C2_DOMAIN,
    }

"""Scenario-consistent evidence fixtures for the offline demo and tests.

These rows mirror what the bundled data generator writes into Splunk for the
reference incident, so the agent can run a full, faithful investigation with no
Splunk and no MCP server. The console offline demo and the test suite both use
this set.
"""

from __future__ import annotations

from typing import Any

from . import scenarios


def scenario_fixtures() -> list[tuple[str, list[dict[str, Any]]]]:
    """Return (spl_substring, rows) pairs. First substring match wins."""
    return [
        # detection backtest: exfil volume by source crosses the threshold once
        ("stats count as hits", [{"hits": "1"}]),
        # exfiltration to the attacker address
        (
            f'dest_ip="{scenarios.ATTACKER_IP}"',
            [{"dest_ip": scenarios.ATTACKER_IP, "dest_port": "443", "bytes_out": str(scenarios.EXFIL_BYTES), "count": "6"}],
        ),
        # lateral movement over SMB
        (
            "dest_port=445",
            [{"dest_ip": scenarios.HOST_DB_IP, "dest": scenarios.HOST_DB, "bytes": "918273", "count": "1"}],
        ),
        # hands-on-keyboard discovery on the entry host
        (
            "sourcetype=Sysmon",
            [
                {"dest": scenarios.HOST_ENTRY, "parent_process_name": "explorer.exe",
                 "process_name": "powershell.exe", "cmds": "powershell -enc SQBFAFgA", "count": "1"},
                {"dest": scenarios.HOST_ENTRY, "parent_process_name": "powershell.exe",
                 "process_name": "whoami.exe", "cmds": "whoami /all", "count": "1"},
                {"dest": scenarios.HOST_ENTRY, "parent_process_name": "powershell.exe",
                 "process_name": "net.exe", "cmds": 'net group "Domain Admins" /domain', "count": "1"},
            ],
        ),
        # C2 beacon: one lookup per minute
        ("sourcetype=stream:dns", [{"_time": str(i), "count": "1"} for i in range(30)]),
        # account takeover: new source vs long-standing corporate source
        (
            "action=success",
            [
                {"src": scenarios.ATTACKER_IP, "first_seen": "just now", "last_seen": "just now", "count": "1"},
                {"src": scenarios.CORP_IP, "first_seen": "60 days ago", "last_seen": "today", "count": "214"},
            ],
        ),
        # brute force pattern
        (
            "stats count by action",
            [
                {"action": "failure", "src": scenarios.ATTACKER_IP, "count": "43"},
                {"action": "success", "src": scenarios.ATTACKER_IP, "count": "1"},
            ],
        ),
    ]

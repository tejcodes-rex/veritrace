"""Generate realistic, CIM-aligned security telemetry with an embedded breach.

Produces a benign baseline of authentication, endpoint, network and DNS events
for a small finance environment, then overlays the intrusion described in
scenarios.py. The field names follow the Splunk Common Information Model so the
agent's SPL reads like real SOC work. Events load through HTTP Event Collector
with their true timestamps so time-based searches and the beacon cadence behave
correctly.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any

from .. import scenarios
from ..config import AppConfig
from ..splunk_io import HecWriter

RNG = random.Random(20260612)


@dataclass(frozen=True)
class Incident:
    """One end-to-end intrusion embedded in the telemetry. Multiple distinct
    incidents prove the detection engine discovers the attack from the data
    rather than relying on any one hard-coded set of entities."""

    user: str
    attacker_ip: str
    entry_host: str
    entry_host_ip: str
    db_host: str
    db_host_ip: str
    c2_domain: str
    exfil_bytes: int
    fail_count: int
    alert_id: str


# Incident 1 is the reference incident from scenarios.py (used by the demo).
INCIDENT_1 = Incident(
    user=scenarios.VICTIM_USER, attacker_ip=scenarios.ATTACKER_IP,
    entry_host=scenarios.HOST_ENTRY, entry_host_ip=scenarios.HOST_ENTRY_IP,
    db_host=scenarios.HOST_DB, db_host_ip=scenarios.HOST_DB_IP,
    c2_domain=scenarios.C2_DOMAIN, exfil_bytes=scenarios.EXFIL_BYTES,
    fail_count=43, alert_id=scenarios.ALERT["alert_id"],
)

# Incident 2 is a genuinely different intrusion: different attacker, account,
# compromised host, database, C2 domain and volume. The agent is given only the
# alert (the user and the source); it discovers everything else from the data.
INCIDENT_2 = Incident(
    user="r.dasilva", attacker_ip="203.0.113.66",
    entry_host="fin-app-05", entry_host_ip="10.20.7.105",
    db_host="db-prod-01", db_host_ip="10.20.9.201",
    c2_domain="edge-metrics-sync.net", exfil_bytes=2_417_483_648,
    fail_count=51, alert_id="SEC-8842",
)

INCIDENTS = [INCIDENT_1, INCIDENT_2]


def alert_for(inc: Incident) -> dict[str, Any]:
    """The alert that would fire for an incident. Carries only what a real alert
    knows: the affected account and the offending source."""
    return {
        "alert_id": inc.alert_id,
        "name": "Brute force authentication success",
        "description": (
            f"Account {inc.user} recorded more than 40 failed logins followed by a "
            f"success within minutes, from a single external source."
        ),
        "severity": "high", "entity": inc.user, "src": inc.attacker_ip,
        "dest": scenarios.VPN_GW, "user": inc.user, "index": scenarios.INDEX,
    }


USERS = ["a.morgan", "s.okoye", "l.chen", "p.novak", "r.dasilva", scenarios.VICTIM_USER, "m.haddad", "k.fischer"]
CORP_HOSTS = {
    "fin-app-05": "10.20.7.105",
    "fin-app-06": "10.20.7.106",
    scenarios.HOST_ENTRY: scenarios.HOST_ENTRY_IP,
    "db-prod-01": "10.20.9.201",
    scenarios.HOST_DB: scenarios.HOST_DB_IP,
    "ws-anaya": "10.20.50.31",
    "ws-tanaka": "10.20.50.34",
}
CORP_SRCS = ["10.20.50.31", scenarios.CORP_IP, "10.20.50.40", "10.20.50.52"]
BENIGN_PROCESSES = [
    ("services.exe", "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs"),
    ("explorer.exe", "outlook.exe", "C:\\Program Files\\Microsoft Office\\outlook.exe"),
    ("explorer.exe", "chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe"),
    ("java.exe", "fin-batch.exe", "D:\\app\\fin-batch.exe --run nightly"),
]
BENIGN_DOMAINS = [
    "office365.com", "windowsupdate.com", "splunkcloud.com", "okta.com",
    "github.com", "slack.com", "salesforce.com",
]


def _payload(event: dict[str, Any], sourcetype: str, epoch: float, index: str) -> dict[str, Any]:
    return {"event": event, "index": index, "sourcetype": sourcetype, "source": "veritrace:sample", "time": round(epoch, 3)}


def _baseline(days: int, index: str, now: float) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    start = now - days * 86400

    # Authentication: steady successful logins, a sprinkle of failures
    for d in range(days):
        day0 = start + d * 86400
        for _ in range(RNG.randint(120, 180)):
            t = day0 + RNG.randint(8 * 3600, 19 * 3600)
            user = RNG.choice(USERS)
            src = RNG.choice(CORP_SRCS)
            if user == scenarios.VICTIM_USER:
                src = scenarios.CORP_IP if RNG.random() > 0.15 else scenarios.HOME_IP
            action = "failure" if RNG.random() < 0.04 else "success"
            payloads.append(_payload(
                {"user": user, "src": src, "dest": scenarios.VPN_GW, "action": action,
                 "app": "sshd", "vendor_product": "Linux Secure"},
                "linux_secure", t, index,
            ))

        # Endpoint: ordinary process activity
        for _ in range(RNG.randint(80, 120)):
            t = day0 + RNG.randint(0, 86400)
            host = RNG.choice(list(CORP_HOSTS))
            parent, proc, cmd = RNG.choice(BENIGN_PROCESSES)
            payloads.append(_payload(
                {"dest": host, "user": RNG.choice(USERS), "parent_process_name": parent,
                 "process_name": proc, "process": cmd, "CommandLine": cmd},
                "Sysmon", t, index,
            ))

        # Network: internal flows, including some normal SMB between servers
        for _ in range(RNG.randint(150, 220)):
            t = day0 + RNG.randint(0, 86400)
            src_host = RNG.choice(list(CORP_HOSTS))
            dst_host = RNG.choice(list(CORP_HOSTS))
            if src_host == dst_host:
                continue
            dport = RNG.choice([443, 443, 445, 3306, 8089, 53])
            b_out = RNG.randint(2_000, 4_000_000)
            payloads.append(_payload(
                {"src_ip": CORP_HOSTS[src_host], "dest_ip": CORP_HOSTS[dst_host],
                 "src": src_host, "dest": dst_host, "src_port": RNG.randint(1024, 65535),
                 "dest_port": dport, "protocol": "tcp", "bytes": b_out + RNG.randint(1000, 50000),
                 "bytes_out": b_out, "bytes_in": RNG.randint(1000, 80000)},
                "stream:tcp", t, index,
            ))

        # DNS: benign lookups
        for _ in range(RNG.randint(120, 200)):
            t = day0 + RNG.randint(0, 86400)
            host = RNG.choice(list(CORP_HOSTS))
            payloads.append(_payload(
                {"src_ip": CORP_HOSTS[host], "src": host, "query": RNG.choice(BENIGN_DOMAINS),
                 "record_type": "A", "answer": f"104.{RNG.randint(16,31)}.{RNG.randint(0,255)}.{RNG.randint(1,254)}"},
                "stream:dns", t, index,
            ))
    return payloads


def _attack(inc: Incident, index: str, now: float, hours_ago: float = 2.0) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    t0 = now - hours_ago * 3600  # when this breach began

    # 1. Brute force: a burst of failures then a success, all from the attacker
    for i in range(inc.fail_count):
        payloads.append(_payload(
            {"user": inc.user, "src": inc.attacker_ip, "dest": scenarios.VPN_GW,
             "action": "failure", "app": "sshd", "vendor_product": "Linux Secure"},
            "linux_secure", t0 + i * 8, index,
        ))
    login_ok = t0 + inc.fail_count * 8 + 5
    payloads.append(_payload(
        {"user": inc.user, "src": inc.attacker_ip, "dest": scenarios.VPN_GW,
         "action": "success", "app": "sshd", "vendor_product": "Linux Secure"},
        "linux_secure", login_ok, index,
    ))

    # 3. Hands-on-keyboard discovery on the entry host
    enc = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    for proc, parent, cmd, dt in [
        ("powershell.exe", "explorer.exe", enc, 120),
        ("whoami.exe", "powershell.exe", "whoami /all", 140),
        ("net.exe", "powershell.exe", 'net group "Domain Admins" /domain', 165),
    ]:
        payloads.append(_payload(
            {"dest": inc.entry_host, "user": inc.user, "parent_process_name": parent,
             "process_name": proc, "process": cmd, "CommandLine": cmd},
            "Sysmon", login_ok + dt, index,
        ))

    # 4. Lateral movement over SMB, then a successful login on the database host
    payloads.append(_payload(
        {"src_ip": inc.entry_host_ip, "dest_ip": inc.db_host_ip, "src": inc.entry_host,
         "dest": inc.db_host, "src_port": 50112, "dest_port": 445, "protocol": "tcp",
         "bytes": 918273, "bytes_out": 512000, "bytes_in": 406273},
        "stream:tcp", login_ok + 300, index,
    ))
    payloads.append(_payload(
        {"user": inc.user, "src": inc.entry_host_ip, "dest": inc.db_host,
         "action": "success", "app": "smb", "vendor_product": "Windows"},
        "linux_secure", login_ok + 320, index,
    ))

    # 5. DNS beaconing from the database host: one lookup per minute for 30 minutes
    for i in range(30):
        payloads.append(_payload(
            {"src_ip": inc.db_host_ip, "src": inc.db_host, "query": inc.c2_domain,
             "record_type": "A", "answer": inc.attacker_ip},
            "stream:dns", login_ok + 360 + i * 60, index,
        ))

    # 6. Bulk exfiltration to the attacker address over a handful of large flows
    remaining = inc.exfil_bytes
    flows = 6
    for i in range(flows):
        chunk = remaining // (flows - i)
        remaining -= chunk
        payloads.append(_payload(
            {"src_ip": inc.db_host_ip, "dest_ip": inc.attacker_ip, "src": inc.db_host,
             "dest": "external", "src_port": 51000 + i, "dest_port": 443, "protocol": "tcp",
             "bytes": chunk + 40000, "bytes_out": chunk, "bytes_in": 38000},
            "stream:tcp", login_ok + 600 + i * 120, index,
        ))
    return payloads


def generate(days: int, index: str, now: float | None = None) -> list[dict[str, Any]]:
    now = now if now is not None else time.time()
    payloads = _baseline(days, index, now)
    # Embed every incident. They are separated in time and use distinct entities,
    # so each one is discovered independently from the affected account outward.
    for offset, inc in enumerate(INCIDENTS):
        payloads += _attack(inc, index, now, hours_ago=2.0 + offset)
    payloads.sort(key=lambda p: p["time"])
    return payloads


def generate_and_load(cfg: AppConfig, days: int = 14) -> int:
    payloads = generate(days, cfg.splunk.index_security)
    HecWriter(cfg.splunk).post_payloads(payloads)
    return len(payloads)

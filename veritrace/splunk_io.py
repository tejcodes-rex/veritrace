"""Thin helpers over the Splunk Enterprise SDK for Python (splunklib).

This module is the only place that talks to Splunk directly. The MCP server
uses it to back its tools, and the ledger writer uses HTTP Event Collector to
record the agent's reasoning back into Splunk. The agent itself never imports
this module: it reaches Splunk only through MCP tools, which is the boundary
that keeps the agent auditable.
"""

from __future__ import annotations

import json
import time
from typing import Any

import requests
import urllib3

from .config import SplunkConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def connect(cfg: SplunkConfig):
    """Return a connected splunklib Service, retrying while Splunk warms up."""
    import splunklib.client as client

    last_err: Exception | None = None
    for _ in range(30):
        try:
            service = client.connect(
                host=cfg.host,
                port=cfg.mgmt_port,
                username=cfg.username,
                password=cfg.password,
                scheme="https",
                verify=cfg.verify_tls,
                autologin=True,
            )
            _ = service.info  # force a round trip
            return service
        except Exception as exc:  # noqa: BLE001 - retry any startup error
            last_err = exc
            time.sleep(5)
    raise RuntimeError(f"Could not connect to Splunk at {cfg.host}:{cfg.mgmt_port}: {last_err}")


def oneshot_search(
    service,
    spl: str,
    earliest: str = "-30d@d",
    latest: str = "now",
    count: int = 500,
) -> list[dict[str, Any]]:
    """Run a blocking search and return rows as plain dicts."""
    import splunklib.results as results

    query = spl if spl.lstrip().startswith(("search", "|")) else f"search {spl}"
    kwargs = {
        "output_mode": "json",
        "count": count,
        "earliest_time": earliest,
        "latest_time": latest,
    }
    response = service.jobs.oneshot(query, **kwargs)
    rows: list[dict[str, Any]] = []
    for item in results.JSONResultsReader(response):
        if isinstance(item, dict):
            rows.append(item)
    return rows


def create_saved_search(service, name: str, search: str, **params) -> None:
    """Create or update a saved search (used to deploy agent-proposed detections)."""
    saved = service.saved_searches
    if name in [s.name for s in saved]:
        saved[name].update(search=search, **params).refresh()
    else:
        saved.create(name, search, **params)


class HecWriter:
    """Writes structured events into Splunk over HTTP Event Collector.

    Used to persist the reasoning ledger and proposed detections so they live in
    Splunk like any other operational data, searchable and replayable.
    """

    def __init__(self, cfg: SplunkConfig):
        self.cfg = cfg
        self.url = f"https://{cfg.host}:{cfg.hec_port}/services/collector/event"
        self.headers = {"Authorization": f"Splunk {cfg.hec_token}"}

    def send(
        self,
        event: dict[str, Any],
        index: str,
        sourcetype: str,
        source: str = "veritrace",
        event_time: float | None = None,
    ) -> None:
        payload = {
            "event": event,
            "index": index,
            "sourcetype": sourcetype,
            "source": source,
            "time": event_time if event_time is not None else time.time(),
        }
        resp = requests.post(
            self.url,
            headers=self.headers,
            data=json.dumps(payload),
            verify=self.cfg.verify_tls,
            timeout=5,
        )
        resp.raise_for_status()

    def post_payloads(self, payloads: list[dict[str, Any]], chunk: int = 500) -> None:
        """Post fully formed HEC payloads (each with its own time/index/sourcetype)."""
        url = f"https://{self.cfg.host}:{self.cfg.hec_port}/services/collector"
        for i in range(0, len(payloads), chunk):
            body = "".join(json.dumps(p) for p in payloads[i : i + chunk])
            resp = requests.post(
                url, headers=self.headers, data=body, verify=self.cfg.verify_tls, timeout=120
            )
            resp.raise_for_status()

    def send_batch(self, events: list[tuple[dict[str, Any], str, str]]) -> None:
        body = "".join(
            json.dumps(
                {"event": e, "index": idx, "sourcetype": st, "source": "veritrace", "time": time.time()}
            )
            for e, idx, st in events
        )
        if not body:
            return
        resp = requests.post(
            f"https://{self.cfg.host}:{self.cfg.hec_port}/services/collector",
            headers=self.headers,
            data=body,
            verify=self.cfg.verify_tls,
            timeout=60,
        )
        resp.raise_for_status()

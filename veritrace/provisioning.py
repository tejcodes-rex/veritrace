"""Provision a fresh Splunk instance for Veritrace.

Creates the three indexes the product uses, enables HTTP Event Collector, and
installs a deterministic HEC token allow-listed for those indexes, all through
the management REST API so the result is identical on every run. Designed to be
called once at stack startup before the sample data is loaded.
"""

from __future__ import annotations

import time

import requests
import urllib3

from .config import SplunkConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _base(cfg: SplunkConfig) -> str:
    return f"https://{cfg.host}:{cfg.mgmt_port}"


def _auth(cfg: SplunkConfig):
    return (cfg.username, cfg.password)


def wait_for_splunk(cfg: SplunkConfig, attempts: int = 60, delay: float = 5.0) -> None:
    url = f"{_base(cfg)}/services/server/info?output_mode=json"
    for i in range(attempts):
        try:
            r = requests.get(url, auth=_auth(cfg), verify=cfg.verify_tls, timeout=10)
            if r.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(delay)
    raise RuntimeError(f"Splunk management API not ready at {_base(cfg)} after {attempts * delay:.0f}s")


def ensure_indexes(cfg: SplunkConfig, names: list[str]) -> None:
    url = f"{_base(cfg)}/services/data/indexes"
    for name in names:
        r = requests.post(
            url, auth=_auth(cfg), verify=cfg.verify_tls, timeout=30,
            data={"name": name, "output_mode": "json"},
        )
        if r.status_code not in (200, 201, 409):
            # 409 means the index already exists, which is fine
            r.raise_for_status()


def ensure_hec(cfg: SplunkConfig, indexes: list[str], token_name: str = "veritrace") -> None:
    # enable HEC globally
    requests.post(
        f"{_base(cfg)}/services/data/inputs/http/http",
        auth=_auth(cfg), verify=cfg.verify_tls, timeout=30,
        data={"disabled": "0", "enableSSL": "1", "output_mode": "json"},
    )
    allowed = ",".join(indexes)
    # create the token with a fixed value, allow-listed for our indexes
    r = requests.post(
        f"{_base(cfg)}/services/data/inputs/http",
        auth=_auth(cfg), verify=cfg.verify_tls, timeout=30,
        data={
            "name": token_name,
            "token": cfg.hec_token,
            "index": indexes[0],
            "indexes": allowed,
            "disabled": "0",
            "output_mode": "json",
        },
    )
    if r.status_code in (200, 201, 409):
        # if it already existed, make sure its index allow-list is current
        requests.post(
            f"{_base(cfg)}/services/data/inputs/http/http%3A%2F%2F{token_name}",
            auth=_auth(cfg), verify=cfg.verify_tls, timeout=30,
            data={"index": indexes[0], "indexes": allowed, "disabled": "0", "output_mode": "json"},
        )
    else:
        r.raise_for_status()


def provision(cfg: SplunkConfig) -> None:
    indexes = [cfg.index_security, cfg.index_ledger, cfg.index_detections]
    wait_for_splunk(cfg)
    ensure_indexes(cfg, indexes)
    ensure_hec(cfg, indexes + ["main"])

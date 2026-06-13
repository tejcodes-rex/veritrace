"""Veritrace custom alert action.

Splunk runs this script when the trigger alert fires. It reads the alert payload
that Splunk sends on stdin, builds a compact alert object, and hands it to the
Veritrace backend, which starts an autonomous investigation. The script uses
only the Python standard library so it runs inside Splunk's bundled interpreter
with no extra packages.
"""

from __future__ import annotations

import json
import sys
import urllib.request


def log(message: str) -> None:
    sys.stderr.write(f"veritrace_alert: {message}\n")


def build_alert(result: dict, settings: dict) -> dict:
    user = result.get("user", "")
    src = result.get("src", "")
    return {
        "alert_id": settings.get("sid", "SEC-LIVE"),
        "name": settings.get("search_name", "Splunk alert"),
        "description": f"Triggered for user {user} from {src}.",
        "severity": "high",
        "entity": user,
        "user": user,
        "src": src,
        "index": "security",
    }


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        log("expected --execute as the first argument")
        return 1

    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError as exc:
        log(f"could not parse payload: {exc}")
        return 2

    config = payload.get("configuration", {})
    api_url = config.get("veritrace_api_url", "http://localhost:8400").rstrip("/")
    alert = build_alert(payload.get("result", {}), payload)

    body = json.dumps({"alert": alert}).encode("utf-8")
    req = urllib.request.Request(
        f"{api_url}/api/investigations",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            log(f"started investigation, status {resp.status}")
    except Exception as exc:  # noqa: BLE001
        log(f"failed to reach Veritrace at {api_url}: {exc}")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

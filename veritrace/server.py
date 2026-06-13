"""Veritrace backend API and live event stream.

Serves the console, starts investigations, streams every reasoning step to the
browser as it is written to the ledger, and lets an analyst approve the proposed
containment actions. Investigations run on a worker thread so the synchronous
agent (which opens its own MCP sessions) never collides with the event loop.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from . import chain, scenarios
from .agent import alert_from_dict
from .config import load_config
from .runtime import build_agent
from .schemas import Investigation

CFG = load_config()


def _find_console_dist() -> Optional[Path]:
    """Locate the built console, regardless of where the package is imported.

    The console is built to ``console/dist`` next to the source tree, but when
    Veritrace runs from an installed wheel (for example in the Docker image) the
    package lives under site-packages while the dist is copied to the working
    directory. Check the source layout, the working directory, and an explicit
    override so the one-origin console is served in every layout.
    """
    candidates = [
        Path(__file__).resolve().parent.parent / "console" / "dist",
        Path.cwd() / "console" / "dist",
    ]
    override = os.environ.get("VERITRACE_CONSOLE_DIST")
    if override:
        candidates.insert(0, Path(override))
    for candidate in candidates:
        if (candidate / "index.html").exists():
            return candidate
    return None


CONSOLE_DIST = _find_console_dist()

app = FastAPI(title="Veritrace", version="1.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


class EventHub:
    """Tiny in-process pub/sub bridging the worker thread to SSE subscribers."""

    def __init__(self) -> None:
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.subscribers: set[asyncio.Queue] = set()

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    def publish(self, kind: str, payload: dict[str, Any]) -> None:
        if not self.loop:
            return
        message = {"kind": kind, "payload": payload}
        for q in list(self.subscribers):
            self.loop.call_soon_threadsafe(q.put_nowait, message)

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)


HUB = EventHub()
STORE: dict[str, Investigation] = {}
ORDER: list[str] = []
_LOCK = threading.Lock()


@app.on_event("startup")
async def _startup() -> None:
    HUB.bind(asyncio.get_running_loop())


def _run_investigation(alert_dict: dict) -> None:
    def on_event(kind: str, payload: dict) -> None:
        if kind == "investigation":
            iid = payload.get("investigation_id")
            with _LOCK:
                if iid in STORE:
                    STORE[iid].status = payload.get("status", "completed")
        HUB.publish(kind, payload)

    agent = build_agent(CFG, on_event=on_event)
    inv = agent.investigate(alert_from_dict(alert_dict))
    with _LOCK:
        STORE[inv.investigation_id] = inv
        if inv.investigation_id not in ORDER:
            ORDER.append(inv.investigation_id)


class StartBody(BaseModel):
    alert: Optional[dict] = None


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "model_provider": CFG.model.provider, "mcp_url": CFG.mcp.url}


@app.get("/api/scenario")
def scenario() -> dict:
    return {
        "alert": scenarios.ALERT,
        "entities": {
            "attacker_ip": scenarios.ATTACKER_IP,
            "c2_domain": scenarios.C2_DOMAIN,
            "victim_user": scenarios.VICTIM_USER,
            "host_entry": scenarios.HOST_ENTRY,
            "host_db": scenarios.HOST_DB,
        },
    }


@app.post("/api/investigations")
def start_investigation(body: StartBody) -> dict:
    alert_dict = body.alert or scenarios.ALERT
    # pre-register a placeholder so the UI can show it as running immediately
    thread = threading.Thread(target=_run_investigation, args=(alert_dict,), daemon=True)
    thread.start()
    return {"status": "started", "alert": alert_dict}


@app.get("/api/investigations")
def list_investigations() -> dict:
    with _LOCK:
        items = [
            {
                "investigation_id": STORE[i].investigation_id,
                "alert_name": STORE[i].alert.name,
                "status": STORE[i].status,
                "verdict": STORE[i].verdict.value if STORE[i].verdict else None,
                "severity": STORE[i].severity.value if STORE[i].severity else None,
                "confidence": STORE[i].confidence,
                "started_at": STORE[i].started_at,
                "mttr_seconds": STORE[i].mttr_seconds,
            }
            for i in ORDER
        ]
    return {"investigations": list(reversed(items))}


@app.get("/api/investigations/{iid}")
def get_investigation(iid: str) -> dict:
    with _LOCK:
        inv = STORE.get(iid)
    if not inv:
        raise HTTPException(404, "investigation not found")
    return inv.model_dump(mode="json")


@app.post("/api/investigations/{iid}/actions/{idx}/approve")
def approve_action(iid: str, idx: int) -> dict:
    with _LOCK:
        inv = STORE.get(iid)
        if not inv or idx >= len(inv.response_actions):
            raise HTTPException(404, "action not found")
        inv.response_actions[idx].status = "approved"
        action = inv.response_actions[idx].model_dump(mode="json")
    HUB.publish("action_approved", {"investigation_id": iid, "index": idx, "action": action})
    return {"status": "approved", "action": action}


@app.post("/api/investigations/{iid}/deploy_detection")
def deploy_detection(iid: str) -> dict:
    with _LOCK:
        inv = STORE.get(iid)
    if not inv or not inv.detection:
        raise HTTPException(404, "no detection to deploy")
    try:
        from .splunk_io import connect, create_saved_search

        service = connect(CFG.splunk)
        create_saved_search(
            service, inv.detection.name, inv.detection.spl,
            cron_schedule=inv.detection.schedule_cron, is_scheduled=1,
        )
        return {"status": "deployed", "name": inv.detection.name}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "detail": str(exc)}


@app.post("/api/investigations/{iid}/verify")
def verify_ledger(iid: str) -> dict:
    """Re-read the ledger and prove the tamper-evident chain is intact.

    The strong proof reads the steps back out of Splunk independently of the
    in-memory run and recomputes the hash chain. If Splunk is not in use (the
    offline demo), it verifies the in-memory chain instead. Either way, altering
    any sealed step makes the recomputed root diverge from the sealed root.
    """
    with _LOCK:
        inv = STORE.get(iid)
    if not inv:
        raise HTTPException(404, "investigation not found")
    expected_root = inv.ledger_root or None
    source = "memory"
    steps = [s.model_dump(mode="json") for s in inv.steps]

    if CFG.evidence_backend != "fixture":
        try:
            import splunklib.client as splunk_client

            from .splunk_io import oneshot_search

            service = splunk_client.connect(
                host=CFG.splunk.host, port=CFG.splunk.mgmt_port,
                username=CFG.splunk.username, password=CFG.splunk.password,
                scheme="https", verify=CFG.splunk.verify_tls, autologin=True,
            )
            spl = (
                f'search index={CFG.splunk.index_ledger} sourcetype=veritrace:reasoning '
                f'investigation_id="{iid}" | sort 0 seq'
            )
            rows = oneshot_search(service, spl, earliest="-7d", latest="now", count=1000)
            # The full event is in _raw as JSON; Splunk only auto-extracts a few
            # top-level fields, so parse _raw to recover exactly what was written.
            parsed = []
            for row in rows:
                raw = row.get("_raw")
                if raw:
                    try:
                        parsed.append(json.loads(raw))
                        continue
                    except (ValueError, TypeError):
                        pass
                parsed.append(row)
            if parsed:
                steps, source = parsed, "splunk"
        except Exception:  # noqa: BLE001 - fall back to the in-memory chain
            pass

    result = chain.verify(iid, steps, expected_root)
    result["source"] = source
    result["investigation_id"] = iid
    return result


@app.get("/api/stream")
async def stream():
    q = await HUB.subscribe()

    async def gen():
        try:
            while True:
                msg = await q.get()
                yield {"event": msg["kind"], "data": json.dumps(msg["payload"])}
        finally:
            HUB.unsubscribe(q)

    return EventSourceResponse(gen())


# Serve the built console if present, so the whole product is one origin.
if CONSOLE_DIST is not None:
    app.mount("/assets", StaticFiles(directory=CONSOLE_DIST / "assets"), name="assets")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(CONSOLE_DIST / "index.html")


def main() -> None:
    import uvicorn

    uvicorn.run("veritrace.server:app", host=CFG.api_host, port=CFG.api_port, reload=False)


if __name__ == "__main__":
    main()

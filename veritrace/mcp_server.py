"""Veritrace MCP server.

A purpose-built Model Context Protocol server that exposes a small, safe set of
Splunk investigation tools to an AI agent. The agent reaches Splunk only through
these tools, so every action it takes against the platform is named, typed and
guard-railed at this boundary.

Run it over SSE (default) for the Docker stack:

    python -m veritrace.mcp_server

or over stdio for a local IDE client:

    VERITRACE_MCP_STDIO=1 python -m veritrace.mcp_server

The tools are deliberately read-oriented. Writing the reasoning ledger back into
Splunk is a separate ingestion path, so the agent cannot mutate platform state
through this server beyond running searches.
"""

from __future__ import annotations

import json
import os
import re

from mcp.server.fastmcp import FastMCP

from .config import load_config
from . import splunk_io

CFG = load_config()

mcp = FastMCP(
    "veritrace-splunk",
    host=os.getenv("VERITRACE_MCP_HOST", "0.0.0.0"),
    port=int(os.getenv("VERITRACE_MCP_PORT", "8052")),
)

# SPL commands that change data, run code, or move data off the platform. The
# agent is an investigator, so none of these are allowed through this server.
_UNSAFE = re.compile(
    r"\|\s*(delete|outputlookup|outputcsv|collect|sendemail|sendalert|script|"
    r"runshellscript|tscollect|mcollect|meventcollect|copyresults)\b",
    re.IGNORECASE,
)

_service = None


def _svc():
    global _service
    if _service is None:
        _service = splunk_io.connect(CFG.splunk)
    return _service


def _validate(spl: str) -> tuple[bool, str]:
    if _UNSAFE.search(spl):
        return False, "Query contains a write, execute or export command and was blocked."
    return True, "ok"


@mcp.tool()
def validate_spl(spl: str) -> str:
    """Check whether an SPL query is safe to run. Returns JSON {safe, reason}."""
    safe, reason = _validate(spl)
    return json.dumps({"safe": safe, "reason": reason})


@mcp.tool()
def splunk_search(
    spl: str,
    earliest: str = "-30d@d",
    latest: str = "now",
    count: int = 500,
) -> str:
    """Run a read-only SPL search and return the results as JSON.

    Use this to gather evidence: authentication records, process activity,
    network flows and DNS lookups. Destructive or data-moving commands are
    rejected. Returns JSON {spl, result_count, results}.
    """
    safe, reason = _validate(spl)
    if not safe:
        return json.dumps({"error": reason, "spl": spl, "result_count": 0, "results": []})
    try:
        rows = splunk_io.oneshot_search(_svc(), spl, earliest=earliest, latest=latest, count=count)
        return json.dumps({"spl": spl, "result_count": len(rows), "results": rows})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc), "spl": spl, "result_count": 0, "results": []})


@mcp.tool()
def splunk_indexes() -> str:
    """List the indexes available on the Splunk instance as JSON."""
    try:
        names = [idx.name for idx in _svc().indexes]
        return json.dumps({"indexes": names})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc), "indexes": []})


@mcp.tool()
def splunk_saved_searches() -> str:
    """List saved searches (detections) defined on the instance as JSON."""
    try:
        items = [{"name": s.name, "search": s.content.get("search", "")} for s in _svc().saved_searches]
        return json.dumps({"saved_searches": items})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc), "saved_searches": []})


@mcp.tool()
def splunk_run_saved_search(name: str) -> str:
    """Run an existing saved search by name and return its results as JSON."""
    try:
        saved = _svc().saved_searches[name]
        job = saved.dispatch()
        import time as _t

        while not job.is_done():
            _t.sleep(0.5)
        import splunklib.results as results

        rows = [r for r in results.JSONResultsReader(job.results(output_mode="json")) if isinstance(r, dict)]
        return json.dumps({"name": name, "result_count": len(rows), "results": rows})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc), "name": name, "results": []})


def main() -> None:
    transport = "stdio" if os.getenv("VERITRACE_MCP_STDIO") else "sse"
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()

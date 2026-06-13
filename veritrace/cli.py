"""Command line interface for Veritrace.

    veritrace serve            start the API and console backend
    veritrace mcp-server       start the Veritrace MCP server
    veritrace load-data        generate and load the sample incident into Splunk
    veritrace investigate      run one investigation and print the result
    veritrace check            check connectivity to Splunk, MCP and the model
"""

from __future__ import annotations

import argparse
import sys

from .config import load_config


def _cmd_serve(args: argparse.Namespace) -> int:
    from .server import main as serve_main

    serve_main()
    return 0


def _cmd_mcp_server(args: argparse.Namespace) -> int:
    from .mcp_server import main as mcp_main

    mcp_main()
    return 0


def _cmd_load_data(args: argparse.Namespace) -> int:
    from .data.generator import generate_and_load

    cfg = load_config()
    count = generate_and_load(cfg, days=args.days)
    print(f"Loaded {count} events into index '{cfg.splunk.index_security}'.")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    from .data.generator import generate_and_load
    from .provisioning import provision

    cfg = load_config()
    print("Provisioning Splunk (indexes + HEC token)...")
    provision(cfg.splunk)
    print("Loading sample security telemetry...")
    count = generate_and_load(cfg, days=args.days)
    print(f"Ready. Loaded {count} events into '{cfg.splunk.index_security}'.")
    return 0


def _cmd_investigate(args: argparse.Namespace) -> int:
    import os

    if args.provider:
        os.environ["VERITRACE_MODEL_PROVIDER"] = args.provider
    cfg = load_config()
    from .agent import alert_from_dict
    from .runtime import build_agent
    from . import scenarios
    from .data.generator import INCIDENTS, alert_for

    # --incident selects which embedded incident to investigate. The agent is
    # given only that incident's alert and discovers the rest from the data,
    # which is how you can see the same engine solve a different attack.
    if args.incident and 1 <= args.incident <= len(INCIDENTS):
        alert = alert_for(INCIDENTS[args.incident - 1])
    else:
        alert = scenarios.ALERT

    agent = build_agent(cfg, evidence_backend=args.backend)
    inv = agent.investigate(alert_from_dict(alert))
    _print_investigation(inv)
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    cfg = load_config()
    ok = True

    print(f"model provider : {cfg.model.provider}")
    print(f"mcp url        : {cfg.mcp.url}")

    try:
        from .splunk_io import connect

        svc = connect(cfg.splunk)
        print(f"splunk         : connected ({svc.info.get('version', 'unknown')})")
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(f"splunk         : NOT reachable ({exc})")

    try:
        from .mcp_client import McpClient

        tools = McpClient(cfg.mcp.url).list_tools()
        print(f"mcp tools      : {', '.join(tools)}")
    except Exception as exc:  # noqa: BLE001
        print(f"mcp tools      : NOT reachable ({exc})")

    return 0 if ok else 1


def _print_investigation(inv) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel

        c = Console()
        c.print(Panel.fit(f"[bold]{inv.alert.name}[/bold]  ({inv.investigation_id})", title="Veritrace"))
        for s in inv.steps:
            head = f"[{s.seq}] {s.kind.value.upper()}  {s.title}"
            body = s.detail or s.model_reasoning
            if s.spl:
                body = f"SPL: {s.spl}\n{body}"
            c.print(Panel(body, title=head, expand=False))
        verdict = inv.verdict.value if inv.verdict else "inconclusive"
        c.print(Panel.fit(
            f"verdict={verdict}  severity={inv.severity.value if inv.severity else '-'}  "
            f"confidence={inv.confidence:.2f}  mttr={inv.mttr_seconds}s  tokens={inv.total_tokens}",
            title="Result",
        ))
        if inv.detection:
            c.print(Panel(
                inv.detection.savedsearch_stanza,
                title=f"Proposed detection (backtest: {inv.detection.backtest_hits_incident} hit, "
                      f"{inv.detection.backtest_false_positives} FP)",
            ))
    except Exception:  # noqa: BLE001 - rich is optional, fall back to plain text
        print(inv.model_dump_json(indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="veritrace", description="Autonomous SOC analyst for Splunk.")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("serve", help="start the API and console backend").set_defaults(func=_cmd_serve)
    sub.add_parser("mcp-server", help="start the Veritrace MCP server").set_defaults(func=_cmd_mcp_server)

    ld = sub.add_parser("load-data", help="generate and load the sample incident into Splunk")
    ld.add_argument("--days", type=int, default=14, help="days of benign baseline to generate")
    ld.set_defaults(func=_cmd_load_data)

    it = sub.add_parser("init", help="provision Splunk indexes + HEC, then load sample data")
    it.add_argument("--days", type=int, default=14, help="days of benign baseline to generate")
    it.set_defaults(func=_cmd_init)

    inv = sub.add_parser("investigate", help="run one investigation and print the result")
    inv.add_argument("--provider", default="", help="override model provider (replay|ollama|vllm|splunk_hosted)")
    inv.add_argument("--backend", default="mcp", choices=["mcp", "direct", "fixture"], help="evidence backend")
    inv.add_argument("--incident", type=int, default=0, help="which embedded incident to investigate (1 or 2); proves generalization")
    inv.set_defaults(func=_cmd_investigate)

    sub.add_parser("check", help="check connectivity").set_defaults(func=_cmd_check)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

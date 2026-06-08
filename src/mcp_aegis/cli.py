"""mcp-aegis CLI — manage and monitor the MCP security gateway."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

import typer

from mcp_aegis import __version__

# ---------------------------------------------------------------------------
# Rich (optional)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint

    _RICH = True
    console = Console()
except ImportError:  # pragma: no cover
    _RICH = False
    console = None  # type: ignore[assignment]


def _plain_print(msg: str) -> None:
    print(msg)


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
_DECISION_COLOUR = {
    "BLOCK": "red",
    "LOG_ONLY": "yellow",
    "ALLOW": "green",
}

_DECISION_ANSI = {
    "BLOCK": "\033[31m",
    "LOG_ONLY": "\033[33m",
    "ALLOW": "\033[32m",
}
_ANSI_RESET = "\033[0m"


def _colour_decision(decision: str) -> str:
    """Return coloured decision string (rich markup or ANSI fallback)."""
    if _RICH:
        colour = _DECISION_COLOUR.get(decision, "white")
        return f"[{colour}]{decision}[/{colour}]"
    code = _DECISION_ANSI.get(decision, "")
    return f"{code}{decision}{_ANSI_RESET}" if code else decision


# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------
_DEFAULT_PORT = 8765
_DEFAULT_DB = Path.home() / ".mcp-aegis" / "audit.db"
_BUILTIN_POLICY = Path(__file__).parent / "policy_default.toml"


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = typer.Typer(
    name="mcp-aegis",
    help="MCP security gateway — blocks dangerous AI agent tool calls by default.",
    add_completion=False,
)

policy_app = typer.Typer(help="Policy inspection and testing commands.")
app.add_typer(policy_app, name="policy")


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------
@app.command()
def serve(
    upstream: str = typer.Option(..., "--upstream", help="Upstream MCP server URL."),
    port: int = typer.Option(_DEFAULT_PORT, "--port", help="Port to listen on."),
    policy: Optional[Path] = typer.Option(
        None, "--policy", help="Path to policy TOML (default: built-in policy_default.toml)."
    ),
    db: Optional[Path] = typer.Option(
        None, "--db", help="Path to audit SQLite DB (default: ~/.mcp-aegis/audit.db)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Log all decisions but never block."
    ),
) -> None:
    """Start the mcp-aegis security gateway in front of an upstream MCP server."""
    import uvicorn

    from mcp_aegis.server import create_app

    resolved_policy = policy or _BUILTIN_POLICY
    resolved_db = db or _DEFAULT_DB

    # Ensure audit DB directory exists
    resolved_db.parent.mkdir(parents=True, exist_ok=True)

    dry_label = "yes" if dry_run else "no"
    banner = (
        f"mcp-aegis {__version__} — MCP Security Gateway\n"
        f"Upstream : {upstream}\n"
        f"Listening: http://localhost:{port}\n"
        f"Policy   : {resolved_policy} (dry-run: {dry_label})\n"
        f"Audit DB : {resolved_db}"
    )
    if _RICH:
        console.print(banner, style="bold cyan")
    else:
        print(banner)

    fastapi_app = create_app(
        upstream_url=upstream,
        policy_path=str(resolved_policy),
        db_path=str(resolved_db),
        dry_run=dry_run,
        port=port,
    )

    uvicorn.run(fastapi_app, host="0.0.0.0", port=port, log_level="warning")


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------
@app.command()
def logs(
    session: Optional[str] = typer.Option(None, "--session", help="Filter by session ID."),
    limit: int = typer.Option(50, "--limit", help="Number of events to display."),
    tail: bool = typer.Option(False, "--tail", help="Stream new events (poll every 1s)."),
    decision: Optional[str] = typer.Option(
        None, "--decision", help="Filter by decision (ALLOW, BLOCK, LOG_ONLY)."
    ),
    db: Optional[Path] = typer.Option(
        None, "--db", help="Path to audit DB (default: ~/.mcp-aegis/audit.db)."
    ),
) -> None:
    """Display and optionally stream audit log events."""
    from mcp_aegis.audit import AuditLog

    resolved_db = db or _DEFAULT_DB
    audit = AuditLog(str(resolved_db))

    def _fetch_rows(since_ts: Optional[float] = None) -> list:
        kwargs: dict = {"limit": limit}
        if session:
            kwargs["session_id"] = session
        if decision:
            kwargs["decision"] = decision
        if since_ts is not None:
            kwargs["since_ts"] = since_ts
        return audit.query(**kwargs)

    def _print_table(rows: list) -> None:
        if not rows:
            return
        if _RICH:
            table = Table(
                show_header=True,
                header_style="bold magenta",
                box=None,
                pad_edge=False,
                collapse_padding=True,
            )
            table.add_column("ts", style="dim", min_width=19)
            table.add_column("session", min_width=8, max_width=8)
            table.add_column("method", min_width=12)
            table.add_column("tool", min_width=20)
            table.add_column("decision", min_width=8)
            table.add_column("rule", min_width=20)
            table.add_column("latency_ms", justify="right", min_width=10)

            for row in rows:
                dec = str(getattr(row, "decision", row.get("decision", "")))
                colour = _DECISION_COLOUR.get(dec, "white")
                table.add_row(
                    str(getattr(row, "ts", row.get("ts", ""))),
                    str(getattr(row, "session_id", row.get("session_id", "")))[:8],
                    str(getattr(row, "method", row.get("method", ""))),
                    str(getattr(row, "tool", row.get("tool", ""))),
                    f"[{colour}]{dec}[/{colour}]",
                    str(getattr(row, "rule", row.get("rule", ""))),
                    str(getattr(row, "latency_ms", row.get("latency_ms", ""))),
                )
            console.print(table)
        else:
            header = f"{'ts':<20} {'session':<8} {'method':<14} {'tool':<22} {'decision':<10} {'rule':<22} {'latency_ms':>10}"
            print(header)
            print("-" * len(header))
            for row in rows:
                dec = str(getattr(row, "decision", row.get("decision", "")))
                coloured = _colour_decision(dec)
                ts = str(getattr(row, "ts", row.get("ts", "")))
                sid = str(getattr(row, "session_id", row.get("session_id", "")))[:8]
                method = str(getattr(row, "method", row.get("method", "")))
                tool = str(getattr(row, "tool", row.get("tool", "")))
                rule = str(getattr(row, "rule", row.get("rule", "")))
                lat = str(getattr(row, "latency_ms", row.get("latency_ms", "")))
                print(f"{ts:<20} {sid:<8} {method:<14} {tool:<22} {coloured:<10} {rule:<22} {lat:>10}")

    if not tail:
        rows = _fetch_rows()
        _print_table(rows)
        return

    # Tail mode: poll for new events using timestamp cursor
    last_ts: float = time.time() - 5.0   # seed with 5s ago to show recent events on start
    try:
        while True:
            rows = _fetch_rows(since_ts=last_ts)
            if rows:
                # query returns newest-first; reverse for chronological display
                rows = list(reversed(rows))
                _print_table(rows)
                last_ts = max(getattr(r, "ts", 0.0) for r in rows) + 0.001
            time.sleep(1)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------
@app.command()
def stats(
    db: Optional[Path] = typer.Option(
        None, "--db", help="Path to audit DB (default: ~/.mcp-aegis/audit.db)."
    ),
) -> None:
    """Print audit statistics from the gateway database."""
    from mcp_aegis.audit import AuditLog

    resolved_db = db or _DEFAULT_DB
    audit = AuditLog(str(resolved_db))
    s = audit.stats()

    total: int = s.get("total_events", 0)
    by_decision: dict = s.get("by_decision", {})
    top_blocked: list = s.get("top_blocked_tools", [])
    top_logged: list = s.get("top_log_only_tools", [])
    session_count: int = s.get("sessions_count", 0)
    last_1h: int = s.get("events_last_hour", 0)
    last_24h: int = s.get("events_last_24h", 0)

    def _pct(n: int) -> str:
        if total == 0:
            return "0.0%"
        return f"{100 * n / total:.1f}%"

    if _RICH:
        console.rule("[bold cyan]mcp-aegis stats[/bold cyan]")
        console.print(f"[bold]Total events:[/bold] {total}")
        console.print(f"[bold]Sessions:[/bold]     {session_count}")
        console.print(f"[bold]Last 1h:[/bold]      {last_1h}")
        console.print(f"[bold]Last 24h:[/bold]     {last_24h}")
        console.print()

        # Decision breakdown
        dec_table = Table(title="By Decision", box=None, pad_edge=False)
        dec_table.add_column("Decision")
        dec_table.add_column("Count", justify="right")
        dec_table.add_column("Pct", justify="right")
        for dec, count in by_decision.items():
            colour = _DECISION_COLOUR.get(dec, "white")
            dec_table.add_row(f"[{colour}]{dec}[/{colour}]", str(count), _pct(count))
        console.print(dec_table)
        console.print()

        # Top blocked tools
        if top_blocked:
            bt = Table(title="Top 5 Blocked Tools", box=None, pad_edge=False)
            bt.add_column("Tool")
            bt.add_column("Count", justify="right")
            for item in top_blocked[:5]:
                bt.add_row(f"[red]{item['tool']}[/red]", str(item['count']))
            console.print(bt)
            console.print()

        # Top logged tools
        if top_logged:
            lt = Table(title="Top 5 Logged Tools", box=None, pad_edge=False)
            lt.add_column("Tool")
            lt.add_column("Count", justify="right")
            for item in top_logged[:5]:
                lt.add_row(f"[yellow]{item['tool']}[/yellow]", str(item['count']))
            console.print(lt)
    else:
        print("=== mcp-aegis stats ===")
        print(f"Total events : {total}")
        print(f"Sessions     : {session_count}")
        print(f"Last 1h      : {last_1h}")
        print(f"Last 24h     : {last_24h}")
        print()
        print("By Decision:")
        for dec, count in by_decision.items():
            print(f"  {dec:<12} {count:>6}  ({_pct(count)})")
        print()
        if top_blocked:
            print("Top 5 Blocked Tools:")
            for item in top_blocked[:5]:
                print(f"  {item['tool']:<30} {item['count']:>6}")
            print()
        if top_logged:
            print("Top 5 Logged Tools:")
            for item in top_logged[:5]:
                print(f"  {item['tool']:<30} {item['count']:>6}")


# ---------------------------------------------------------------------------
# policy test
# ---------------------------------------------------------------------------
@policy_app.command("test")
def policy_test(
    tool_name: str = typer.Argument(..., help="Tool name to evaluate against the policy."),
    policy: Optional[Path] = typer.Option(
        None, "--policy", help="Path to policy TOML (default: built-in)."
    ),
    method: str = typer.Option("tools/call", "--method", help="MCP method (default: tools/call)."),
) -> None:
    """Evaluate a tool name against the active policy and print the decision."""
    from mcp_aegis.policy import PolicyEngine

    resolved_policy = policy or _BUILTIN_POLICY
    engine = PolicyEngine.from_default() if policy is None else PolicyEngine(str(resolved_policy))
    result = engine.test(tool_name, method)

    decision = str(getattr(result, "decision", result.get("decision", "")))
    rule_name = str(getattr(result, "rule_name", result.get("rule_name", "")))
    reason = str(getattr(result, "reason", result.get("reason", "")))

    if _RICH:
        colour = _DECISION_COLOUR.get(decision, "white")
        console.print(f"[bold]Decision:[/bold] [{colour}]{decision}[/{colour}]")
        console.print(f"[bold]Rule    :[/bold] {rule_name}")
        console.print(f"[bold]Reason  :[/bold] {reason}")
    else:
        print(f"Decision : {_colour_decision(decision)}")
        print(f"Rule     : {rule_name}")
        print(f"Reason   : {reason}")

    # Exit codes: 0 = ALLOW, 1 = BLOCK, 2 = LOG_ONLY
    exit_codes = {"ALLOW": 0, "BLOCK": 1, "LOG_ONLY": 2}
    sys.exit(exit_codes.get(decision, 1))


# ---------------------------------------------------------------------------
# policy show
# ---------------------------------------------------------------------------
@policy_app.command("show")
def policy_show(
    policy: Optional[Path] = typer.Option(
        None, "--policy", help="Path to policy TOML (default: built-in)."
    ),
) -> None:
    """Display all rules from the active policy file."""
    import tomllib  # Python 3.11+

    # Fallback for Python < 3.11
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            typer.echo("tomllib/tomli not available. Install tomli for Python < 3.11.", err=True)
            raise typer.Exit(1)

    resolved_policy = policy or _BUILTIN_POLICY
    with open(resolved_policy, "rb") as f:
        data = tomllib.load(f)

    rules = data.get("rules", [])

    if _RICH:
        table = Table(title=f"Policy: {resolved_policy}", box=None, pad_edge=False)
        table.add_column("name", style="bold")
        table.add_column("decision")
        table.add_column("tools")
        table.add_column("methods")
        for rule in rules:
            dec = rule.get("decision", "")
            colour = _DECISION_COLOUR.get(dec, "white")
            table.add_row(
                rule.get("name", ""),
                f"[{colour}]{dec}[/{colour}]",
                ", ".join(rule.get("tools", [])),
                ", ".join(rule.get("methods", [])),
            )
        console.print(table)
    else:
        header = f"{'name':<30} {'decision':<10} {'tools':<40} {'methods':<30}"
        print(header)
        print("-" * len(header))
        for rule in rules:
            dec = rule.get("decision", "")
            print(
                f"{rule.get('name', ''):<30} {_colour_decision(dec):<10} "
                f"{', '.join(rule.get('tools', [])):<40} "
                f"{', '.join(rule.get('methods', [])):<30}"
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app()

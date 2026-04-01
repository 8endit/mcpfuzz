"""Rich CLI reporter for mcpfuzz scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcpfuzz.engine.runner import ScanReport

SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

STATUS_COLORS = {
    "fail": "red bold",
    "warn": "yellow",
    "pass": "green",
    "error": "dim",
}


def print_report(report: ScanReport, console: Console | None = None) -> None:
    """Print a formatted scan report to the terminal."""
    console = console or Console()

    # Header
    passed, total = report.score
    console.print()
    console.print(
        Panel(
            f"[bold]mcpfuzz Security Report[/bold]\n"
            f"Target: {report.target}\n"
            f"Tools discovered: {report.tools_discovered}\n"
            f"Timestamp: {report.timestamp}",
            border_style="blue",
        )
    )

    if not report.results:
        console.print("[yellow]No test results — no applicable patterns matched.[/yellow]")
        return

    # Results table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Pattern", width=22)
    table.add_column("Tool", width=18)
    table.add_column("Status", width=6)
    table.add_column("Detail", ratio=1)

    for r in report.results:
        sev_style = SEVERITY_COLORS.get(r.severity, "")
        stat_style = STATUS_COLORS.get(r.status, "")
        table.add_row(
            f"[{sev_style}]{r.severity.upper()}[/{sev_style}]",
            r.pattern_name,
            r.tool_name,
            f"[{stat_style}]{r.status.upper()}[/{stat_style}]",
            r.detail[:80],
        )

    console.print(table)

    # Summary
    console.print()
    summary_parts = [f"Score: {passed}/{total}"]
    if report.critical_fails:
        summary_parts.append(f"[red bold]{report.critical_fails} CRITICAL[/red bold]")
    if report.failed - report.critical_fails:
        summary_parts.append(f"[red]{report.failed - report.critical_fails} HIGH/MED fails[/red]")
    if report.warnings:
        summary_parts.append(f"[yellow]{report.warnings} WARN[/yellow]")
    console.print(" | ".join(summary_parts))
    console.print()

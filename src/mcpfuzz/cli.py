"""mcpfuzz CLI — Dynamic security testing for MCP servers."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console

from mcpfuzz.connector.stdio import StdioConnector
from mcpfuzz.discovery.discover import initialize, discover_tools
from mcpfuzz.engine.runner import run_scan
from mcpfuzz.patterns.registry import PatternRegistry
from mcpfuzz.reporter.cli_report import print_report
from mcpfuzz.reporter.json_report import write_json
from mcpfuzz.reporter.md_report import write_markdown

console = Console()

# Resolve patterns directory — next to pyproject.toml
PATTERNS_DIR = Path(__file__).parent.parent.parent / "patterns"


@click.group()
@click.version_option(version="0.1.0", prog_name="mcpfuzz")
def main() -> None:
    """mcpfuzz — Dynamic security testing for MCP servers."""


@main.command()
@click.option("--stdio", "stdio_cmd", help="Command to start MCP server via stdio")
@click.option("--http", "http_url", help="URL of remote MCP server (HTTP/SSE)")
@click.option("--config", "config_path", type=click.Path(exists=True), help="MCP config file path")
@click.option("--patterns", "pattern_filter", help="Comma-separated pattern IDs to run")
@click.option("--format", "output_format", type=click.Choice(["cli", "json", "md"]), default="cli")
@click.option("--output", "output_path", type=click.Path(), help="Output file path")
@click.option("--timeout", default=5.0, help="Timeout per tool call in seconds")
def scan(
    stdio_cmd: str | None,
    http_url: str | None,
    config_path: str | None,
    pattern_filter: str | None,
    output_format: str,
    output_path: str | None,
    timeout: float,
) -> None:
    """Scan an MCP server for security vulnerabilities."""
    if not stdio_cmd and not http_url and not config_path:
        console.print("[red]Error: Provide --stdio, --http, or --config[/red]")
        sys.exit(1)

    if http_url:
        console.print("[yellow]HTTP connector not yet implemented. Use --stdio for now.[/yellow]")
        sys.exit(1)

    if config_path:
        console.print("[yellow]Config file parsing not yet implemented. Use --stdio for now.[/yellow]")
        sys.exit(1)

    # Load patterns
    registry = PatternRegistry()
    if PATTERNS_DIR.exists():
        registry.load_from_directory(PATTERNS_DIR)
    else:
        console.print(f"[red]Patterns directory not found: {PATTERNS_DIR}[/red]")
        sys.exit(1)

    if pattern_filter:
        filter_ids = [p.strip() for p in pattern_filter.split(",")]
        patterns = registry.filter_by_ids(filter_ids)
        if not patterns:
            console.print(f"[red]No patterns matched filter: {pattern_filter}[/red]")
            sys.exit(1)
    else:
        patterns = registry.list_all()

    # Use stderr for progress messages when outputting structured formats to stdout
    log = Console(stderr=True) if output_format != "cli" and not output_path else console

    log.print(f"[blue]Loaded {len(patterns)} test patterns[/blue]")
    pattern_names = ", ".join(p.name for p in patterns)
    log.print(f"[dim]Patterns: {pattern_names}[/dim]")

    asyncio.run(_run_scan(stdio_cmd, patterns, output_format, output_path, timeout, log))


async def _run_scan(
    stdio_cmd: str | None,
    patterns: list,
    output_format: str,
    output_path: str | None,
    timeout: float,
    log: Console | None = None,
) -> None:
    assert stdio_cmd
    log = log or console
    connector = StdioConnector(stdio_cmd, timeout=timeout)

    try:
        async with connector:
            log.print(f"[blue]Connecting to: {stdio_cmd}[/blue]")
            server_info = await initialize(connector)
            log.print(f"[green]Connected. Server: {server_info.get('serverInfo', {}).get('name', 'unknown')}[/green]")

            log.print("[blue]Discovering tools...[/blue]")
            tools = await discover_tools(connector)
            log.print(f"[green]Found {len(tools)} tools: {', '.join(t.name for t in tools)}[/green]")

            log.print("[blue]Running security tests...[/blue]")
            report = await run_scan(connector, tools, patterns, target_name=stdio_cmd, timeout=timeout)

            # Output
            if output_format == "json":
                if output_path:
                    write_json(report, Path(output_path))
                    log.print(f"[green]JSON report written to {output_path}[/green]")
                else:
                    from mcpfuzz.reporter.json_report import generate_json
                    click.echo(generate_json(report))
            elif output_format == "md":
                if output_path:
                    write_markdown(report, Path(output_path))
                    log.print(f"[green]Markdown report written to {output_path}[/green]")
                else:
                    from mcpfuzz.reporter.md_report import generate_markdown
                    click.echo(generate_markdown(report))
            else:
                print_report(report, console)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option("--stdio", "stdio_cmd", help="Command to start MCP server via stdio")
@click.option("--http", "http_url", help="URL of remote MCP server (HTTP/SSE)")
@click.option("--timeout", default=5.0, help="Timeout per request in seconds")
def discover(stdio_cmd: str | None, http_url: str | None, timeout: float) -> None:
    """Discover tools on an MCP server (no testing)."""
    if not stdio_cmd and not http_url:
        console.print("[red]Error: Provide --stdio or --http[/red]")
        sys.exit(1)

    if http_url:
        console.print("[yellow]HTTP connector not yet implemented.[/yellow]")
        sys.exit(1)

    asyncio.run(_run_discover(stdio_cmd, timeout))


async def _run_discover(stdio_cmd: str | None, timeout: float) -> None:
    assert stdio_cmd
    connector = StdioConnector(stdio_cmd, timeout=timeout)

    try:
        async with connector:
            console.print(f"[blue]Connecting to: {stdio_cmd}[/blue]")
            server_info = await initialize(connector)
            console.print(f"[green]Connected. Server: {server_info.get('serverInfo', {}).get('name', 'unknown')}[/green]")

            tools = await discover_tools(connector)
            console.print(f"\n[bold]Discovered {len(tools)} tools:[/bold]\n")
            for tool in tools:
                console.print(f"  [cyan]{tool.name}[/cyan]: {tool.description}")
                for param in tool.parameters.values():
                    req = " [red](required)[/red]" if param.required else ""
                    console.print(f"    - {param.name}: {param.type}{req}")
                console.print()
    except Exception as e:
        console.print(f"[red]Discovery failed: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option("--catalog", "catalog_path", default="catalog/servers.yaml",
              type=click.Path(), help="Path to server catalog YAML")
@click.option("--category", help="Filter by category (filesystem, database, fetch, code_exec, etc.)")
@click.option("--type", "server_type", help="Filter by type (real, demo_vuln, reference)")
@click.option("--min-stars", default=0, type=int, help="Minimum GitHub stars")
@click.option("--output-dir", default="reports/batch", help="Directory for JSON reports")
@click.option("--timeout", default=10.0, help="Timeout per tool call in seconds")
@click.option("--id", "server_id", help="Scan only a specific server by ID")
def batch(
    catalog_path: str,
    category: str | None,
    server_type: str | None,
    min_stars: int,
    output_dir: str,
    timeout: float,
    server_id: str | None,
) -> None:
    """Batch scan servers from the catalog."""
    from mcpfuzz.catalog import load_catalog, filter_catalog

    cat_path = Path(catalog_path)
    if not cat_path.exists():
        console.print(f"[red]Catalog not found: {cat_path}[/red]")
        sys.exit(1)

    entries = load_catalog(cat_path)
    console.print(f"[blue]Loaded {len(entries)} servers from catalog[/blue]")

    if server_id:
        entries = [e for e in entries if e.id == server_id]
    else:
        entries = filter_catalog(entries, category=category, server_type=server_type, min_stars=min_stars)

    # Only scan servers that have a command defined
    scannable = [e for e in entries if e.command]
    skipped = [e for e in entries if not e.command]

    console.print(f"[blue]Scannable: {len(scannable)} | Skipped (no command): {len(skipped)}[/blue]")

    if not scannable:
        console.print("[yellow]No servers to scan.[/yellow]")
        return

    # Load patterns
    registry = PatternRegistry()
    registry.load_from_directory(PATTERNS_DIR)
    patterns = registry.list_all()

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    asyncio.run(_run_batch(scannable, patterns, out_path, timeout))


async def _run_batch(
    servers: list,
    patterns: list,
    output_dir: Path,
    timeout: float,
) -> None:
    """Run batch scan across multiple servers."""
    from datetime import datetime
    from mcpfuzz.reporter.json_report import generate_json

    results_summary = []
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for i, entry in enumerate(servers, 1):
        console.print()
        console.print(f"[bold blue]--- [{i}/{len(servers)}] {entry.name} ({entry.id}) ---[/bold blue]")
        console.print(f"  Category: {', '.join(entry.category)} | Type: {entry.type} | Stars: {entry.stars}")

        connector = StdioConnector(entry.command, timeout=timeout)

        try:
            async with connector:
                server_info = await initialize(connector)
                server_name = server_info.get("serverInfo", {}).get("name", entry.id)
                console.print(f"  [green]Connected: {server_name}[/green]")

                tools = await discover_tools(connector)
                console.print(f"  [green]Tools: {len(tools)} — {', '.join(t.name for t in tools)}[/green]")

                report = await run_scan(connector, tools, patterns, target_name=entry.name, timeout=timeout)

                # Save individual report
                report_file = output_dir / f"{entry.id}_{ts}.json"
                report_file.write_text(generate_json(report), encoding="utf-8")

                # Summary
                passed, total = report.score
                broken = sum(1 for r in report.results if r.evidence.get("broken_promise"))
                summary = {
                    "id": entry.id,
                    "name": entry.name,
                    "category": entry.category,
                    "type": entry.type,
                    "stars": entry.stars,
                    "tools": report.tools_discovered,
                    "total": total,
                    "passed": passed,
                    "failed": report.failed,
                    "critical": report.critical_fails,
                    "warnings": report.warnings,
                    "broken_promises": broken,
                    "status": "scanned",
                }
                results_summary.append(summary)

                # Print inline result
                if report.critical_fails:
                    console.print(f"  [red bold]  {report.critical_fails} CRITICAL | {report.failed} fails[/red bold]")
                elif report.failed:
                    console.print(f"  [red]  {report.failed} fails[/red]")
                else:
                    console.print(f"  [green]  CLEAN ({passed}/{total})[/green]")
                if broken:
                    console.print(f"  [red bold]  {broken} BROKEN PROMISES[/red bold]")

        except Exception as e:
            console.print(f"  [red]  FAILED: {e}[/red]")
            results_summary.append({
                "id": entry.id,
                "name": entry.name,
                "category": entry.category,
                "type": entry.type,
                "stars": entry.stars,
                "status": "error",
                "error": str(e),
            })

    # Write batch summary
    import json
    summary_file = output_dir / f"batch_summary_{ts}.json"
    summary_file.write_text(json.dumps(results_summary, indent=2), encoding="utf-8")

    # Print final table
    console.print()
    console.print("[bold]--- BATCH SUMMARY ---[/bold]")
    from rich.table import Table
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", width=3)
    table.add_column("Server", width=30)
    table.add_column("Type", width=10)
    table.add_column("Category", width=15)
    table.add_column("Stars", justify="right", width=6)
    table.add_column("Tools", justify="right", width=5)
    table.add_column("Score", width=8)
    table.add_column("Verdict", width=20)

    for i, s in enumerate(results_summary, 1):
        if s.get("status") == "error":
            verdict = "[dim]ERROR[/dim]"
            score = "—"
            tools = "—"
        elif s.get("critical", 0) > 0:
            verdict = f"[red bold]{s['critical']} CRITICAL[/red bold]"
            score = f"{s['passed']}/{s['total']}"
            tools = str(s["tools"])
        elif s.get("failed", 0) > 0:
            verdict = f"[red]{s['failed']} fails[/red]"
            score = f"{s['passed']}/{s['total']}"
            tools = str(s["tools"])
        else:
            verdict = "[green]CLEAN[/green]"
            score = f"{s['passed']}/{s['total']}"
            tools = str(s["tools"])

        table.add_row(
            str(i),
            s["name"][:30],
            s["type"],
            ", ".join(s["category"])[:15],
            str(s.get("stars", "")),
            tools,
            score,
            verdict,
        )

    console.print(table)
    console.print(f"\n[dim]Reports saved to: {output_dir}/[/dim]")
    console.print(f"[dim]Summary: {summary_file}[/dim]")


if __name__ == "__main__":
    main()

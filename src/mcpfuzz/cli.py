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


if __name__ == "__main__":
    main()

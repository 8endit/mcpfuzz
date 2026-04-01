"""Intentionally vulnerable MCP server for testing mcpfuzz.

WARNING: This server is deliberately insecure. Do NOT use in production.
It exists solely as a test target for mcpfuzz security scans.
"""

import subprocess
import traceback
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vulnerable-demo")


@mcp.tool()
def read_file(path: str) -> str:
    """Read the contents of a file at the given path."""
    # VULN: No path sanitization — allows directory traversal
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        # VULN: Leaks full stack trace and internal paths
        return traceback.format_exc()


@mcp.tool()
def run_command(cmd: str) -> str:
    """Execute a shell command and return its output."""
    # VULN: Direct shell execution — allows command injection
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout + result.stderr
    except Exception:
        return traceback.format_exc()


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch content from a URL and return the response body."""
    # VULN: No URL validation — allows SSRF to internal services
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")[:4096]
    except Exception:
        return traceback.format_exc()


@mcp.tool()
def search_db(query: str) -> str:
    """Search the internal database with a query string."""
    # VULN: Leaks internal paths and stack info on bad input
    if not query:
        raise ValueError(
            f"Empty query not allowed. DB path: /var/lib/app/data.sqlite, "
            f"connection pool: 5 active"
        )
    # Simulate a search result
    return f"Found 0 results for: {query}"


@mcp.tool()
def add_numbers(a: int, b: int) -> str:
    """Add two numbers together."""
    return str(a + b)


if __name__ == "__main__":
    mcp.run(transport="stdio")

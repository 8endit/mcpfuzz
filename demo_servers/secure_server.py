"""Properly secured MCP server for testing mcpfuzz.

This server implements security best practices and should pass all mcpfuzz scans.
"""

import ipaddress
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("secure-demo")

ALLOWED_DIR = Path(__file__).parent / "sandbox"
ALLOWED_COMMANDS = {"echo", "date", "whoami", "hostname"}
ALLOWED_DOMAINS = {"example.com", "httpbin.org"}


@mcp.tool()
def read_file(path: str) -> str:
    """Read the contents of a file within the sandbox directory."""
    try:
        ALLOWED_DIR.mkdir(exist_ok=True)
        resolved = (ALLOWED_DIR / path).resolve()
        if not str(resolved).startswith(str(ALLOWED_DIR.resolve())):
            return "Error: Access denied — path is outside the allowed directory."
        if not resolved.is_file():
            return "Error: File not found."
        return resolved.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return "Error: Could not read file."


@mcp.tool()
def run_command(cmd: str) -> str:
    """Execute an allowed command (echo, date, whoami, hostname)."""
    parts = cmd.split()
    if not parts or parts[0] not in ALLOWED_COMMANDS:
        return f"Error: Command not allowed. Permitted: {', '.join(sorted(ALLOWED_COMMANDS))}"
    try:
        result = subprocess.run(
            parts, capture_output=True, text=True, timeout=5, shell=False
        )
        return result.stdout.strip()
    except Exception:
        return "Error: Command execution failed."


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch content from an allowed URL (example.com, httpbin.org only)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return "Error: Only HTTP(S) URLs are allowed."
        hostname = parsed.hostname or ""
        if hostname not in ALLOWED_DOMAINS:
            return f"Error: Domain not allowed. Permitted: {', '.join(sorted(ALLOWED_DOMAINS))}"
        # Block private/internal IPs
        try:
            for info in __import__("socket").getaddrinfo(hostname, None):
                addr = info[4][0]
                if ipaddress.ip_address(addr).is_private:
                    return "Error: Requests to private IP addresses are not allowed."
        except Exception:
            return "Error: Could not resolve hostname."
        import urllib.request

        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")[:4096]
    except Exception:
        return "Error: Could not fetch URL."


@mcp.tool()
def search_db(query: str) -> str:
    """Search the database with a query string."""
    if not query or not query.strip():
        return "Error: Query must not be empty."
    return f"Found 0 results for: {query}"


@mcp.tool()
def add_numbers(a: int, b: int) -> str:
    """Add two numbers together."""
    return str(a + b)


if __name__ == "__main__":
    # Create sandbox dir with a test file
    ALLOWED_DIR.mkdir(exist_ok=True)
    test_file = ALLOWED_DIR / "hello.txt"
    if not test_file.exists():
        test_file.write_text("Hello from the sandbox!")
    mcp.run(transport="stdio")

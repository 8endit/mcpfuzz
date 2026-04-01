"""Promise vs Reality — detect security claims in tool descriptions.

Analyzes tool and parameter descriptions for security promises like
"sandboxed", "read-only", "restricted to working directory", etc.
When a test contradicts a promise, the finding becomes more severe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mcpfuzz.utils.jsonrpc import ToolInfo


# Security promise patterns — regex + what they claim
PROMISE_PATTERNS: list[tuple[str, str]] = [
    # Path/filesystem restrictions
    (r"(?:only|restrict|limit|confin)\w*\s+(?:to|within|inside)\s+[\w/\\\"']+", "path_restriction"),
    (r"sandbox\w*", "sandboxed"),
    (r"safe\s+directory", "path_restriction"),
    (r"allowed?\s+(?:dir|directory|path|folder)", "path_restriction"),
    (r"working\s+directory\s+only", "path_restriction"),
    (r"(?:no|prevent|block)\w*\s+(?:traversal|escape)", "traversal_protection"),
    (r"chroot", "sandboxed"),

    # Read-only / no-write
    (r"read[\s-]*only", "read_only"),
    (r"(?:no|cannot|won't|will not)\s+(?:write|modify|delete|create)", "read_only"),

    # Input validation
    (r"(?:sanitiz|validat|escap)\w+\s+(?:input|path|query|parameter)", "input_validation"),
    (r"(?:parameteriz|prepar)\w+\s+(?:query|statement)", "parameterized_queries"),
    (r"(?:prevent|protect|safe)\w*\s+(?:from\s+)?(?:injection|sqli)", "injection_protection"),

    # Access control
    (r"allow[\s-]*list", "allowlist"),
    (r"(?:authenticat|authoriz)\w+", "auth_required"),
    (r"(?:no|block|prevent)\s+(?:private|internal|metadata)\s+(?:ip|address|endpoint)", "ssrf_protection"),

    # Execution restrictions
    (r"(?:no|prevent|block)\s+(?:arbitrary|shell|system)\s+(?:command|execution|code)", "execution_restriction"),
    (r"(?:only|restrict)\w*\s+(?:allow|permit)\w*\s+(?:command|operation)", "command_allowlist"),
]


@dataclass
class SecurityPromise:
    """A detected security claim from a tool's description."""
    claim_type: str
    source: str  # "tool_description", "param_description", "server_name"
    text: str  # The actual text that matched
    tool_name: str


@dataclass
class PromiseAnalysis:
    """Analysis of all security promises for a server."""
    promises: list[SecurityPromise] = field(default_factory=list)

    def has_promise(self, claim_type: str, tool_name: str | None = None) -> bool:
        """Check if a specific promise exists, optionally for a specific tool."""
        for p in self.promises:
            if p.claim_type == claim_type:
                if tool_name is None or p.tool_name == tool_name or p.tool_name == "__server__":
                    return True
        return False

    def get_promises_for_tool(self, tool_name: str) -> list[SecurityPromise]:
        """Get all promises relevant to a specific tool."""
        return [p for p in self.promises if p.tool_name == tool_name or p.tool_name == "__server__"]

    def get_broken_promise_text(self, claim_type: str, tool_name: str) -> str | None:
        """Get the original promise text for a broken claim."""
        for p in self.promises:
            if p.claim_type == claim_type and (p.tool_name == tool_name or p.tool_name == "__server__"):
                return p.text
        return None


# Map from pattern_id to which promise types it can break
PATTERN_BREAKS_PROMISE: dict[str, list[str]] = {
    "path_traversal": ["path_restriction", "sandboxed", "traversal_protection"],
    "command_injection": ["execution_restriction", "command_allowlist", "sandboxed", "input_validation"],
    "ssrf": ["ssrf_protection", "allowlist"],
    "sql_injection": ["parameterized_queries", "injection_protection", "input_validation"],
    "error_leakage": ["input_validation"],
    "prompt_injection": [],
    "input_validation": ["input_validation"],
    "resource_exhaustion": [],
}


def analyze_promises(tools: list[ToolInfo], server_name: str = "") -> PromiseAnalysis:
    """Scan all tool descriptions for security promises."""
    analysis = PromiseAnalysis()

    # Check server name
    if server_name:
        _scan_text(server_name, "__server__", "server_name", analysis)

    for tool in tools:
        # Check tool description
        if tool.description:
            _scan_text(tool.description, tool.name, "tool_description", analysis)

        # Check parameter descriptions
        for param in tool.parameters.values():
            if param.description:
                _scan_text(param.description, tool.name, "param_description", analysis)

    return analysis


def _scan_text(text: str, tool_name: str, source: str, analysis: PromiseAnalysis) -> None:
    """Scan a text for security promise patterns."""
    text_lower = text.lower()
    for regex, claim_type in PROMISE_PATTERNS:
        match = re.search(regex, text_lower)
        if match:
            analysis.promises.append(SecurityPromise(
                claim_type=claim_type,
                source=source,
                text=match.group(0),
                tool_name=tool_name,
            ))


def check_broken_promises(
    pattern_id: str,
    tool_name: str,
    test_failed: bool,
    analysis: PromiseAnalysis,
) -> dict[str, Any] | None:
    """Check if a test failure breaks a security promise.

    Returns a dict with broken promise details, or None.
    """
    if not test_failed:
        return None

    breakable = PATTERN_BREAKS_PROMISE.get(pattern_id, [])
    for claim_type in breakable:
        if analysis.has_promise(claim_type, tool_name):
            promise_text = analysis.get_broken_promise_text(claim_type, tool_name)
            return {
                "broken_promise": True,
                "claim_type": claim_type,
                "promised": promise_text,
                "reality": f"Test '{pattern_id}' succeeded despite claim of '{claim_type}'",
            }

    return None

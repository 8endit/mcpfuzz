"""Match tools to applicable test patterns based on parameter schemas."""

from __future__ import annotations

import re

from mcpfuzz.patterns.loader import Pattern
from mcpfuzz.utils.jsonrpc import ToolInfo


def match_tool_to_patterns(tool: ToolInfo, patterns: list[Pattern]) -> list[Pattern]:
    """Determine which patterns are applicable to a given tool."""
    matched = []
    for pattern in patterns:
        if pattern.applies_to_all:
            matched.append(pattern)
            continue
        if _tool_matches_pattern(tool, pattern):
            matched.append(pattern)
    return matched


def _tool_matches_pattern(tool: ToolInfo, pattern: Pattern) -> bool:
    """Check if any tool parameter matches the pattern's target criteria."""
    for param in tool.parameters.values():
        if param.type != pattern.param_type:
            continue
        for name_pattern in pattern.param_name_patterns:
            if re.search(name_pattern, param.name, re.IGNORECASE):
                return True
    return False


def find_matching_params(tool: ToolInfo, pattern: Pattern) -> list[str]:
    """Find which parameter names in a tool match a pattern's target criteria."""
    if pattern.applies_to_all:
        return [p.name for p in tool.parameters.values() if p.type == "string"]
    matching = []
    for param in tool.parameters.values():
        if param.type != pattern.param_type:
            continue
        for name_pattern in pattern.param_name_patterns:
            if re.search(name_pattern, param.name, re.IGNORECASE):
                matching.append(param.name)
                break
    return matching

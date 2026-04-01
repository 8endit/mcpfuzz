"""JSON-RPC 2.0 message helpers for MCP protocol communication."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


_next_id = 0


def _get_id() -> int:
    global _next_id
    _next_id += 1
    return _next_id


def make_request(method: str, params: dict[str, Any] | None = None) -> tuple[int, str]:
    """Build a JSON-RPC 2.0 request. Returns (id, json_string)."""
    req_id = _get_id()
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return req_id, json.dumps(msg)


def make_notification(method: str, params: dict[str, Any] | None = None) -> str:
    """Build a JSON-RPC 2.0 notification (no id, no response expected)."""
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def parse_response(data: str) -> dict[str, Any]:
    """Parse a JSON-RPC 2.0 response string into a dict."""
    return json.loads(data)


@dataclass
class ToolInfo:
    """Parsed MCP tool information."""
    name: str
    description: str
    parameters: dict[str, ParamInfo] = field(default_factory=dict)


@dataclass
class ParamInfo:
    """Parsed parameter information from a tool's input schema."""
    name: str
    type: str
    required: bool = False
    description: str = ""

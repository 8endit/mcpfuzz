"""Shared fixtures for mcpfuzz tests."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from pathlib import Path

import pytest

from mcpfuzz.connector.base import BaseConnector
from mcpfuzz.utils.jsonrpc import ToolInfo, ParamInfo


PATTERNS_DIR = Path(__file__).parent.parent / "patterns"


class MockConnector(BaseConnector):
    """Mock connector that returns predefined responses."""

    def __init__(self, responses: dict[str, Any] | None = None):
        self._responses = responses or {}
        self._calls: list[tuple[str, dict[str, Any] | None]] = []

    async def connect(self) -> None:
        pass

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._calls.append((method, params))
        if method in self._responses:
            handler = self._responses[method]
            if callable(handler):
                return handler(params)
            return handler
        return {"result": {}}

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._calls.append((method, params))

    async def close(self) -> None:
        pass

    @property
    def calls(self) -> list[tuple[str, dict[str, Any] | None]]:
        return self._calls


def make_tool_info(name: str, description: str, params: dict[str, str], required: list[str] | None = None) -> ToolInfo:
    """Helper to create ToolInfo for tests."""
    required = required or []
    tool = ToolInfo(name=name, description=description)
    for pname, ptype in params.items():
        tool.parameters[pname] = ParamInfo(
            name=pname,
            type=ptype,
            required=pname in required,
        )
    return tool


def mock_tools_list_response(tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a mock tools/list response."""
    return {
        "result": {
            "tools": tools,
        }
    }


def mock_tool_call_response(text: str, is_error: bool = False) -> dict[str, Any]:
    """Build a mock tools/call response."""
    return {
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }
    }

"""Tests for MCP server discovery."""

import asyncio

import pytest

from mcpfuzz.discovery.discover import initialize, discover_tools
from tests.conftest import MockConnector, mock_tools_list_response


@pytest.fixture
def mock_connector():
    return MockConnector(responses={
        "initialize": {
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test-server", "version": "1.0"},
            }
        },
        "tools/list": mock_tools_list_response([
            {
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path"},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "add_numbers",
                "description": "Add two numbers",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "integer"},
                        "b": {"type": "integer"},
                    },
                    "required": ["a", "b"],
                },
            },
        ]),
    })


def test_initialize(mock_connector):
    result = asyncio.run(initialize(mock_connector))
    assert result["serverInfo"]["name"] == "test-server"
    # Should have sent initialize request + notifications/initialized
    methods = [c[0] for c in mock_connector.calls]
    assert "initialize" in methods
    assert "notifications/initialized" in methods


def test_discover_tools(mock_connector):
    asyncio.run(initialize(mock_connector))
    tools = asyncio.run(discover_tools(mock_connector))
    assert len(tools) == 2
    assert tools[0].name == "read_file"
    assert "path" in tools[0].parameters
    assert tools[0].parameters["path"].required is True
    assert tools[1].name == "add_numbers"
    assert tools[1].parameters["a"].type == "integer"

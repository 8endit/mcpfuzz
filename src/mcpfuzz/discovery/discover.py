"""MCP server discovery — initialize handshake and enumerate tools."""

from __future__ import annotations

from mcpfuzz.connector.base import BaseConnector
from mcpfuzz.utils.jsonrpc import ToolInfo, ParamInfo


async def initialize(connector: BaseConnector) -> dict:
    """Perform the MCP initialize handshake."""
    resp = await connector.send_request("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "mcpfuzz", "version": "0.1.0"},
    })
    # Send initialized notification
    await connector.send_notification("notifications/initialized")
    return resp.get("result", {})


async def discover_tools(connector: BaseConnector) -> list[ToolInfo]:
    """Call tools/list and parse the response into ToolInfo objects."""
    resp = await connector.send_request("tools/list")
    result = resp.get("result", {})
    raw_tools = result.get("tools", [])
    tools = []
    for raw in raw_tools:
        tool = ToolInfo(
            name=raw.get("name", ""),
            description=raw.get("description", ""),
        )
        schema = raw.get("inputSchema", {})
        properties = schema.get("properties", {})
        required_params = set(schema.get("required", []))
        for param_name, param_schema in properties.items():
            tool.parameters[param_name] = ParamInfo(
                name=param_name,
                type=param_schema.get("type", "string"),
                required=param_name in required_params,
                description=param_schema.get("description", ""),
            )
        tools.append(tool)
    return tools

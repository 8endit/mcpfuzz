"""HTTP/SSE transport connector for remote MCP servers."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urljoin

from mcpfuzz.connector.base import BaseConnector
from mcpfuzz.utils.jsonrpc import make_request, make_notification


class HttpConnector(BaseConnector):
    """Connect to an MCP server via Streamable HTTP."""

    def __init__(self, url: str, timeout: float = 5.0):
        self._url = url
        self._timeout = timeout
        self._session_id: str | None = None

    async def connect(self) -> None:
        # HTTP connector is stateless per-request; connection is implicit
        pass

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        import aiohttp

        req_id, req_str = make_request(method, params)
        headers = {"Content-Type": "application/json"}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self._url,
                data=req_str,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self._timeout),
            ) as resp:
                # Capture session ID from response headers
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self._session_id = sid

                content_type = resp.headers.get("Content-Type", "")
                if "text/event-stream" in content_type:
                    # SSE response — parse event stream
                    return await self._parse_sse_response(resp, req_id)
                else:
                    return await resp.json()

    async def _parse_sse_response(self, resp: Any, req_id: int) -> dict[str, Any]:
        """Parse SSE event stream to extract the JSON-RPC response."""
        async for line in resp.content:
            line_str = line.decode("utf-8", errors="replace").strip()
            if line_str.startswith("data: "):
                data_str = line_str[6:]
                try:
                    msg = json.loads(data_str)
                    if msg.get("id") == req_id:
                        return msg
                except json.JSONDecodeError:
                    continue
        return {"error": {"message": "No response received from SSE stream"}}

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        import aiohttp

        notif_str = make_notification(method, params)
        headers = {"Content-Type": "application/json"}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self._url,
                data=notif_str,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self._timeout),
            ) as resp:
                pass  # Notifications don't expect responses

    async def close(self) -> None:
        pass  # HTTP is stateless; nothing to close

    @property
    def server_name(self) -> str:
        return self._url

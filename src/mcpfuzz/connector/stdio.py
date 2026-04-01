"""Stdio transport connector — spawns MCP server as subprocess.

Supports both framing modes:
- Content-Length (HTTP-style headers) — used by newer MCP SDK
- Newline-delimited JSON — used by older/custom servers

Auto-detects the server's framing mode on the first response, then
uses Content-Length framing for all outgoing messages (accepted by both).
"""

from __future__ import annotations

import asyncio
import json
import shlex
import sys
from typing import Any

from mcpfuzz.connector.base import BaseConnector
from mcpfuzz.utils.jsonrpc import make_request, make_notification


class StdioConnector(BaseConnector):
    """Connect to an MCP server via stdio (subprocess)."""

    def __init__(self, command: str, timeout: float = 5.0):
        self._command = command
        self._timeout = timeout
        self._process: asyncio.subprocess.Process | None = None
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._framing: str = "auto"  # "auto", "content-length", "newline"

    async def connect(self) -> None:
        if sys.platform == "win32":
            parts = self._command.split()
        else:
            parts = shlex.split(self._command)
        self._process = await asyncio.create_subprocess_exec(
            *parts,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._reader_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        """Read messages from stdout, auto-detecting framing mode."""
        assert self._process and self._process.stdout
        while True:
            try:
                msg = await self._read_one_message()
            except (asyncio.IncompleteReadError, ConnectionError):
                break
            if msg is None:
                break
            msg_id = msg.get("id")
            if msg_id is not None and msg_id in self._pending:
                self._pending[msg_id].set_result(msg)

    async def _read_one_message(self) -> dict[str, Any] | None:
        """Read a single JSON-RPC message, auto-detecting framing."""
        assert self._process and self._process.stdout
        stdout = self._process.stdout

        if self._framing == "content-length":
            return await self._read_content_length(stdout)
        elif self._framing == "newline":
            return await self._read_newline(stdout)

        # Auto-detect: peek at the first non-empty data
        while True:
            line = await stdout.readline()
            if not line:
                return None
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            if line_str.lower().startswith("content-length:"):
                # Content-Length framing detected
                self._framing = "content-length"
                length = int(line_str.split(":", 1)[1].strip())
                # Read until empty line (end of headers)
                while True:
                    header_line = await stdout.readline()
                    if not header_line or header_line.strip() == b"":
                        break
                # Read body
                body = await stdout.readexactly(length)
                return json.loads(body.decode("utf-8", errors="replace"))
            else:
                # Try to parse as JSON (newline-delimited)
                try:
                    msg = json.loads(line_str)
                    self._framing = "newline"
                    return msg
                except json.JSONDecodeError:
                    # Skip non-JSON lines (e.g. server log output)
                    continue

    async def _read_content_length(self, stdout: asyncio.StreamReader) -> dict[str, Any] | None:
        """Read a Content-Length framed message."""
        length = None
        while True:
            line = await stdout.readline()
            if not line:
                return None
            line_str = line.decode("utf-8", errors="replace").strip()
            if line_str.lower().startswith("content-length:"):
                length = int(line_str.split(":", 1)[1].strip())
            elif line_str == "":
                # End of headers
                if length is not None:
                    body = await stdout.readexactly(length)
                    return json.loads(body.decode("utf-8", errors="replace"))
                # Empty line without content-length — keep reading
                continue

    async def _read_newline(self, stdout: asyncio.StreamReader) -> dict[str, Any] | None:
        """Read a newline-delimited JSON message."""
        while True:
            line = await stdout.readline()
            if not line:
                return None
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                return json.loads(line_str)
            except json.JSONDecodeError:
                continue

    def _frame_message(self, message: str) -> bytes:
        """Frame a message for sending.

        Sends Content-Length framing followed by a trailing newline.
        - Content-Length servers read the header + body, ignore trailing newline
        - Newline-delimited servers skip the header lines (not valid JSON),
          then read the JSON body line
        This makes the same bytes work for both framing modes.
        """
        body = message.encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
        return header + body + b"\n"

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self._process and self._process.stdin
        req_id, req_str = make_request(method, params)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future
        self._process.stdin.write(self._frame_message(req_str))
        await self._process.stdin.drain()
        try:
            result = await asyncio.wait_for(future, timeout=self._timeout)
        finally:
            self._pending.pop(req_id, None)
        return result

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        assert self._process and self._process.stdin
        notif_str = make_notification(method, params)
        self._process.stdin.write(self._frame_message(notif_str))
        await self._process.stdin.drain()

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._process:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                self._process.kill()

    @property
    def server_name(self) -> str:
        return self._command.split()[-1] if self._command else "unknown"

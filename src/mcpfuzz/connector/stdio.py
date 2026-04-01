"""Stdio transport connector — spawns MCP server as subprocess."""

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
        assert self._process and self._process.stdout
        while True:
            line = await self._process.stdout.readline()
            if not line:
                break
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                msg = json.loads(line_str)
            except json.JSONDecodeError:
                continue
            msg_id = msg.get("id")
            if msg_id is not None and msg_id in self._pending:
                self._pending[msg_id].set_result(msg)

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self._process and self._process.stdin
        req_id, req_str = make_request(method, params)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future
        self._process.stdin.write((req_str + "\n").encode("utf-8"))
        await self._process.stdin.drain()
        try:
            result = await asyncio.wait_for(future, timeout=self._timeout)
        finally:
            self._pending.pop(req_id, None)
        return result

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        assert self._process and self._process.stdin
        notif_str = make_notification(method, params)
        self._process.stdin.write((notif_str + "\n").encode("utf-8"))
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

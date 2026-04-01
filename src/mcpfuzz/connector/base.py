"""Abstract base connector for MCP server communication."""

from __future__ import annotations

import abc
from typing import Any


class BaseConnector(abc.ABC):
    """Abstract connector interface for MCP servers."""

    @abc.abstractmethod
    async def connect(self) -> None:
        """Establish connection to the MCP server."""

    @abc.abstractmethod
    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and return the response."""

    @abc.abstractmethod
    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Close the connection."""

    async def __aenter__(self) -> BaseConnector:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

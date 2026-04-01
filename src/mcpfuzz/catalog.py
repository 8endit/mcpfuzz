"""Server catalog — load and filter MCP servers from the registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ServerEntry:
    """A single MCP server in the catalog."""
    id: str
    name: str
    repo: str
    category: list[str]
    type: str  # "real", "demo_vuln", "reference"
    sdk: str = "mcp_fastmcp"
    stars: int = 0
    command: str = ""
    install: str = ""
    copy_path: str = ""
    setup: str = ""
    patch: str = ""
    env: dict[str, str] = field(default_factory=dict)
    notes: str = ""

    @property
    def is_real(self) -> bool:
        return self.type == "real"

    @property
    def is_python(self) -> bool:
        return self.sdk in ("mcp_fastmcp", "fastmcp", "mcp_low", "custom")

    @property
    def is_node(self) -> bool:
        return self.sdk == "node"

    @property
    def clone_url(self) -> str:
        if self.repo.startswith("http"):
            return self.repo
        return ""


def load_catalog(path: Path) -> list[ServerEntry]:
    """Load the server catalog from a YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    entries = []
    for raw in data.get("servers", []):
        cat = raw.get("category", [])
        if isinstance(cat, str):
            cat = [cat]
        entries.append(ServerEntry(
            id=raw["id"],
            name=raw.get("name", raw["id"]),
            repo=raw.get("repo", ""),
            category=cat,
            type=raw.get("type", "real"),
            sdk=raw.get("sdk", "mcp_fastmcp"),
            stars=raw.get("stars", 0),
            command=raw.get("command", ""),
            install=raw.get("install", ""),
            copy_path=raw.get("copy_path", ""),
            setup=raw.get("setup", ""),
            patch=raw.get("patch", ""),
            env=raw.get("env", {}),
            notes=raw.get("notes", ""),
        ))
    return entries


def filter_catalog(
    entries: list[ServerEntry],
    category: str | None = None,
    server_type: str | None = None,
    sdk: str | None = None,
    min_stars: int = 0,
) -> list[ServerEntry]:
    """Filter catalog entries by criteria."""
    result = entries
    if category:
        result = [e for e in result if category in e.category]
    if server_type:
        result = [e for e in result if e.type == server_type]
    if sdk:
        result = [e for e in result if e.sdk == sdk]
    if min_stars > 0:
        result = [e for e in result if e.stars >= min_stars]
    return result

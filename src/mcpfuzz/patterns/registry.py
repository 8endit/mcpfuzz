"""Registry for managing loaded security test patterns."""

from __future__ import annotations

from pathlib import Path

from mcpfuzz.patterns.loader import Pattern, load_patterns_dir


class PatternRegistry:
    """Manages the set of available test patterns."""

    def __init__(self) -> None:
        self._patterns: dict[str, Pattern] = {}

    def load_from_directory(self, directory: Path) -> None:
        for pattern in load_patterns_dir(directory):
            self._patterns[pattern.id] = pattern

    def add(self, pattern: Pattern) -> None:
        self._patterns[pattern.id] = pattern

    def get(self, pattern_id: str) -> Pattern | None:
        return self._patterns.get(pattern_id)

    def list_all(self) -> list[Pattern]:
        return list(self._patterns.values())

    def filter_by_ids(self, ids: list[str]) -> list[Pattern]:
        return [p for p in self._patterns.values() if p.id in ids]

    def __len__(self) -> int:
        return len(self._patterns)

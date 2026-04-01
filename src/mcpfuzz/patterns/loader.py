"""Load YAML pattern definitions into structured Pattern objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Payload:
    value: str
    description: str = ""
    platform: str = "any"


@dataclass
class Detection:
    response_contains_any: list[str] = field(default_factory=list)
    response_not_contains: list[str] = field(default_factory=list)


@dataclass
class Pattern:
    id: str
    name: str
    severity: str
    description: str
    param_name_patterns: list[str] = field(default_factory=list)
    param_type: str = "string"
    payloads: list[Payload] = field(default_factory=list)
    detection: Detection = field(default_factory=Detection)
    applies_to_all: bool = False

    @classmethod
    def from_yaml(cls, data: dict) -> Pattern:
        target = data.get("target_params", {})
        det_data = data.get("detection", {})
        return cls(
            id=data["id"],
            name=data["name"],
            severity=data["severity"],
            description=data.get("description", ""),
            param_name_patterns=target.get("param_name_patterns", []),
            param_type=target.get("param_type", "string"),
            applies_to_all=target.get("applies_to_all", False),
            payloads=[
                Payload(
                    value=str(p["value"]),
                    description=p.get("description", ""),
                    platform=p.get("platform", "any"),
                )
                for p in data.get("payloads", [])
            ],
            detection=Detection(
                response_contains_any=det_data.get("response_contains_any", []),
                response_not_contains=det_data.get("response_not_contains", []),
            ),
        )


def load_pattern_file(path: Path) -> Pattern:
    """Load a single YAML pattern file."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return Pattern.from_yaml(data)


def load_patterns_dir(directory: Path) -> list[Pattern]:
    """Load all YAML pattern files from a directory."""
    patterns = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        patterns.append(load_pattern_file(yaml_file))
    return patterns

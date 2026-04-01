"""Tests for pattern loading and registry."""

from pathlib import Path

from mcpfuzz.patterns.loader import load_pattern_file, load_patterns_dir, Pattern
from mcpfuzz.patterns.registry import PatternRegistry


PATTERNS_DIR = Path(__file__).parent.parent / "patterns"


def test_load_path_traversal_pattern():
    p = load_pattern_file(PATTERNS_DIR / "path_traversal.yaml")
    assert p.id == "path_traversal"
    assert p.severity == "critical"
    assert len(p.payloads) >= 3
    assert "path" in p.param_name_patterns
    assert len(p.detection.response_contains_any) > 0


def test_load_all_patterns():
    patterns = load_patterns_dir(PATTERNS_DIR)
    assert len(patterns) == 7
    ids = {p.id for p in patterns}
    assert "path_traversal" in ids
    assert "command_injection" in ids
    assert "ssrf" in ids
    assert "input_validation" in ids
    assert "error_leakage" in ids
    assert "resource_exhaustion" in ids
    assert "prompt_injection" in ids


def test_registry_load_and_filter():
    reg = PatternRegistry()
    reg.load_from_directory(PATTERNS_DIR)
    assert len(reg) == 7

    filtered = reg.filter_by_ids(["ssrf", "path_traversal"])
    assert len(filtered) == 2
    assert {p.id for p in filtered} == {"ssrf", "path_traversal"}


def test_registry_get():
    reg = PatternRegistry()
    reg.load_from_directory(PATTERNS_DIR)
    p = reg.get("command_injection")
    assert p is not None
    assert p.severity == "critical"
    assert reg.get("nonexistent") is None


def test_applies_to_all_patterns():
    patterns = load_patterns_dir(PATTERNS_DIR)
    all_patterns = [p for p in patterns if p.applies_to_all]
    assert len(all_patterns) >= 2  # input_validation, error_leakage, resource_exhaustion

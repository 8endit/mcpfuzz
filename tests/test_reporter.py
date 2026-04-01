"""Tests for report generation."""

import json

from mcpfuzz.engine.runner import ScanReport, TestResult
from mcpfuzz.reporter.json_report import generate_json
from mcpfuzz.reporter.md_report import generate_markdown


def _make_report() -> ScanReport:
    return ScanReport(
        target="test-server",
        timestamp="2026-04-01T12:00:00Z",
        tools_discovered=3,
        results=[
            TestResult(
                pattern_id="path_traversal",
                pattern_name="Path Traversal",
                severity="critical",
                tool_name="read_file",
                status="fail",
                detail="Vulnerable: Unix passwd file traversal",
                evidence={"input": "../../../etc/passwd", "output_snippet": "root:x:0:0"},
            ),
            TestResult(
                pattern_id="ssrf",
                pattern_name="SSRF",
                severity="critical",
                tool_name="fetch_url",
                status="pass",
                detail="All payloads handled safely.",
            ),
            TestResult(
                pattern_id="error_leakage",
                pattern_name="Error Leakage",
                severity="high",
                tool_name="search_db",
                status="warn",
                detail="Potential issues detected",
            ),
        ],
    )


def test_json_report_structure():
    report = _make_report()
    output = generate_json(report)
    data = json.loads(output)
    assert data["target"] == "test-server"
    assert data["tools_discovered"] == 3
    assert len(data["results"]) == 3
    assert data["score"]["total"] == 3
    assert data["score"]["passed"] == 1
    assert data["score"]["failed"] == 1
    assert data["score"]["critical_fails"] == 1


def test_markdown_report_contains_sections():
    report = _make_report()
    md = generate_markdown(report)
    assert "# mcpfuzz Security Report" in md
    assert "test-server" in md
    assert "| CRITICAL |" in md
    assert "## Failure Details" in md
    assert "Path Traversal" in md


def test_report_score_properties():
    report = _make_report()
    assert report.passed == 1
    assert report.failed == 1
    assert report.warnings == 1
    assert report.critical_fails == 1
    assert report.score == (1, 3)

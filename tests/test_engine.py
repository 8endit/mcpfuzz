"""Tests for the test engine (matcher + runner)."""

import asyncio
from pathlib import Path

import pytest

from mcpfuzz.engine.matcher import match_tool_to_patterns, find_matching_params
from mcpfuzz.engine.promises import analyze_promises, check_broken_promises
from mcpfuzz.engine.runner import run_scan, _evaluate_response, _extract_response_text
from mcpfuzz.patterns.loader import load_patterns_dir, Pattern, Payload, Detection
from mcpfuzz.utils.jsonrpc import ToolInfo, ParamInfo
from tests.conftest import MockConnector, make_tool_info, mock_tool_call_response


PATTERNS_DIR = Path(__file__).parent.parent / "patterns"


class TestMatcher:
    def test_path_traversal_matches_file_tool(self):
        patterns = load_patterns_dir(PATTERNS_DIR)
        path_trav = [p for p in patterns if p.id == "path_traversal"][0]

        tool = make_tool_info("read_file", "Read a file", {"path": "string"}, ["path"])
        matched = match_tool_to_patterns(tool, [path_trav])
        assert len(matched) == 1

    def test_ssrf_matches_url_tool(self):
        patterns = load_patterns_dir(PATTERNS_DIR)
        ssrf = [p for p in patterns if p.id == "ssrf"][0]

        tool = make_tool_info("fetch_url", "Fetch URL", {"url": "string"}, ["url"])
        matched = match_tool_to_patterns(tool, [ssrf])
        assert len(matched) == 1

    def test_no_match_for_numeric_tool(self):
        patterns = load_patterns_dir(PATTERNS_DIR)
        path_trav = [p for p in patterns if p.id == "path_traversal"][0]

        tool = make_tool_info("add", "Add numbers", {"a": "integer", "b": "integer"})
        matched = match_tool_to_patterns(tool, [path_trav])
        assert len(matched) == 0

    def test_applies_to_all_matches_everything(self):
        patterns = load_patterns_dir(PATTERNS_DIR)
        input_val = [p for p in patterns if p.id == "input_validation"][0]

        tool = make_tool_info("anything", "Does stuff", {"x": "string"})
        matched = match_tool_to_patterns(tool, [input_val])
        assert len(matched) == 1

    def test_find_matching_params(self):
        patterns = load_patterns_dir(PATTERNS_DIR)
        path_trav = [p for p in patterns if p.id == "path_traversal"][0]

        tool = make_tool_info("reader", "Read files", {
            "filepath": "string",
            "encoding": "string",
        })
        params = find_matching_params(tool, path_trav)
        assert "filepath" in params
        assert "encoding" not in params


class TestResponseEvaluation:
    def test_fail_on_vuln_indicator(self):
        pattern = Pattern(
            id="test", name="Test", severity="high", description="",
            detection=Detection(
                response_contains_any=["root:"],
                response_not_contains=["error", "denied"],
            ),
        )
        payload = Payload(value="test")
        assert _evaluate_response("root:x:0:0:root", pattern, payload) == "fail"

    def test_pass_on_safe_response(self):
        pattern = Pattern(
            id="test", name="Test", severity="high", description="",
            detection=Detection(
                response_contains_any=["root:"],
                response_not_contains=["error", "denied"],
            ),
        )
        payload = Payload(value="test")
        assert _evaluate_response("File not found", pattern, payload) == "pass"

    def test_warn_on_mixed(self):
        pattern = Pattern(
            id="test", name="Test", severity="high", description="",
            detection=Detection(
                response_contains_any=["root:"],
                response_not_contains=["error"],
            ),
        )
        payload = Payload(value="test")
        assert _evaluate_response("error: root: permission denied", pattern, payload) == "warn"


class TestExtractResponse:
    def test_extract_text_content(self):
        resp = {"result": {"content": [{"type": "text", "text": "hello world"}]}}
        assert _extract_response_text(resp) == "hello world"

    def test_extract_error(self):
        resp = {"error": {"message": "not found", "data": "details"}}
        assert "not found" in _extract_response_text(resp)

    def test_extract_empty(self):
        resp = {"result": {}}
        text = _extract_response_text(resp)
        assert isinstance(text, str)


class TestRunner:
    def test_scan_vulnerable_tool(self):
        """Simulate scanning a tool that returns /etc/passwd contents."""
        connector = MockConnector(responses={
            "tools/call": lambda params: mock_tool_call_response(
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin"
            ),
        })
        tool = make_tool_info("read_file", "Read", {"path": "string"}, ["path"])
        patterns = load_patterns_dir(PATTERNS_DIR)
        path_trav = [p for p in patterns if p.id == "path_traversal"][0]

        report = asyncio.run(run_scan(connector, [tool], [path_trav], "test"))
        fails = [r for r in report.results if r.status == "fail"]
        assert len(fails) >= 1
        assert fails[0].severity == "critical"

    def test_scan_secure_tool(self):
        """Simulate scanning a tool that properly rejects traversal."""
        connector = MockConnector(responses={
            "tools/call": lambda params: mock_tool_call_response(
                "Error: Access denied — path is outside the allowed directory."
            ),
        })
        tool = make_tool_info("read_file", "Read", {"path": "string"}, ["path"])
        patterns = load_patterns_dir(PATTERNS_DIR)
        path_trav = [p for p in patterns if p.id == "path_traversal"][0]

        report = asyncio.run(run_scan(connector, [tool], [path_trav], "test"))
        fails = [r for r in report.results if r.status == "fail"]
        assert len(fails) == 0


class TestPromises:
    def test_detect_path_restriction(self):
        tool = ToolInfo(
            name="read_file",
            description="Read files only within the sandbox directory.",
            parameters={"path": ParamInfo(name="path", type="string", required=True)},
        )
        analysis = analyze_promises([tool])
        assert len(analysis.promises) >= 1
        assert analysis.has_promise("path_restriction", "read_file")

    def test_detect_sandbox(self):
        tool = ToolInfo(
            name="exec",
            description="Execute code in a sandboxed environment.",
            parameters={"code": ParamInfo(name="code", type="string", required=True)},
        )
        analysis = analyze_promises([tool])
        assert analysis.has_promise("sandboxed", "exec")

    def test_detect_read_only(self):
        tool = ToolInfo(
            name="query",
            description="Execute read-only SQL queries against the database.",
            parameters={"sql": ParamInfo(name="sql", type="string", required=True)},
        )
        analysis = analyze_promises([tool])
        assert analysis.has_promise("read_only", "query")

    def test_no_promises_generic_description(self):
        tool = ToolInfo(
            name="add",
            description="Add two numbers together.",
            parameters={"a": ParamInfo(name="a", type="integer", required=True)},
        )
        analysis = analyze_promises([tool])
        assert len(analysis.promises) == 0

    def test_broken_promise_detection(self):
        tool = ToolInfo(
            name="read_file",
            description="Read files restricted to the working directory only.",
            parameters={"path": ParamInfo(name="path", type="string", required=True)},
        )
        analysis = analyze_promises([tool])
        assert analysis.has_promise("path_restriction", "read_file")

        broken = check_broken_promises("path_traversal", "read_file", True, analysis)
        assert broken is not None
        assert broken["broken_promise"] is True
        assert broken["claim_type"] == "path_restriction"

    def test_no_broken_promise_when_test_passes(self):
        tool = ToolInfo(
            name="read_file",
            description="Read files restricted to the working directory only.",
            parameters={"path": ParamInfo(name="path", type="string", required=True)},
        )
        analysis = analyze_promises([tool])
        broken = check_broken_promises("path_traversal", "read_file", False, analysis)
        assert broken is None

    def test_broken_promise_in_scan_report(self):
        """End-to-end: a vulnerable tool with a security promise should have broken_promise in evidence."""
        connector = MockConnector(responses={
            "tools/call": lambda params: mock_tool_call_response(
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin"
            ),
        })
        tool = ToolInfo(
            name="read_file",
            description="Read files only within the sandbox directory.",
            parameters={"path": ParamInfo(name="path", type="string", required=True, description="File path")},
        )
        patterns = load_patterns_dir(PATTERNS_DIR)
        path_trav = [p for p in patterns if p.id == "path_traversal"][0]

        report = asyncio.run(run_scan(connector, [tool], [path_trav], "test"))
        fails = [r for r in report.results if r.status == "fail"]
        assert len(fails) >= 1
        assert fails[0].evidence.get("broken_promise") is not None
        assert "BROKEN PROMISE" in fails[0].detail

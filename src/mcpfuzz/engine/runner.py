"""Test engine — orchestrates security test execution against MCP tools."""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from mcpfuzz.connector.base import BaseConnector
from mcpfuzz.engine.matcher import match_tool_to_patterns, find_matching_params
from mcpfuzz.patterns.loader import Pattern, Payload
from mcpfuzz.utils.jsonrpc import ToolInfo


@dataclass
class TestResult:
    pattern_id: str
    pattern_name: str
    severity: str
    tool_name: str
    status: str  # "pass", "fail", "warn", "error"
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanReport:
    target: str
    timestamp: str = ""
    tools_discovered: int = 0
    tools: list[ToolInfo] = field(default_factory=list)
    results: list[TestResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == "pass")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == "fail")

    @property
    def warnings(self) -> int:
        return sum(1 for r in self.results if r.status == "warn")

    @property
    def critical_fails(self) -> int:
        return sum(1 for r in self.results if r.status == "fail" and r.severity == "critical")

    @property
    def score(self) -> tuple[int, int]:
        total = len(self.results)
        return (self.passed, total)


async def run_scan(
    connector: BaseConnector,
    tools: list[ToolInfo],
    patterns: list[Pattern],
    target_name: str = "unknown",
    timeout: float = 5.0,
) -> ScanReport:
    """Run all applicable patterns against all discovered tools."""
    from datetime import datetime, timezone

    report = ScanReport(
        target=target_name,
        timestamp=datetime.now(timezone.utc).isoformat(),
        tools_discovered=len(tools),
        tools=tools,
    )

    for tool in tools:
        matched_patterns = match_tool_to_patterns(tool, patterns)
        for pattern in matched_patterns:
            result = await _run_pattern_against_tool(connector, tool, pattern, timeout)
            report.results.append(result)

    return report


async def _run_pattern_against_tool(
    connector: BaseConnector,
    tool: ToolInfo,
    pattern: Pattern,
    timeout: float,
) -> TestResult:
    """Execute a single pattern's payloads against a tool and evaluate results."""
    matching_params = find_matching_params(tool, pattern)
    if not matching_params:
        # For applies_to_all patterns with no string params, skip
        return TestResult(
            pattern_id=pattern.id,
            pattern_name=pattern.name,
            severity=pattern.severity,
            tool_name=tool.name,
            status="pass",
            detail="No matching parameters found — pattern not applicable.",
        )

    target_param = matching_params[0]
    fail_evidence: dict[str, Any] = {}
    warn_indicators: list[str] = []

    for payload in pattern.payloads:
        # Skip platform-specific payloads on wrong platform
        if payload.platform == "unix" and sys.platform == "win32":
            continue
        if payload.platform == "windows" and sys.platform != "win32":
            continue

        # Build tool call arguments — fill required params with safe defaults
        args = _build_call_args(tool, target_param, payload.value)

        try:
            resp = await asyncio.wait_for(
                connector.send_request("tools/call", {
                    "name": tool.name,
                    "arguments": args,
                }),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            # Timeout could indicate resource exhaustion
            if pattern.id == "resource_exhaustion":
                warn_indicators.append(f"Timeout on payload: {payload.description}")
            continue
        except Exception as e:
            continue

        response_text = _extract_response_text(resp)
        status = _evaluate_response(response_text, pattern, payload)

        if status == "fail":
            fail_evidence = {
                "input": payload.value,
                "param": target_param,
                "payload_desc": payload.description,
                "output_snippet": response_text[:500],
            }
            return TestResult(
                pattern_id=pattern.id,
                pattern_name=pattern.name,
                severity=pattern.severity,
                tool_name=tool.name,
                status="fail",
                detail=f"Vulnerable: {payload.description}",
                evidence=fail_evidence,
            )
        elif status == "warn":
            warn_indicators.append(f"{payload.description}: {response_text[:200]}")

    if warn_indicators:
        return TestResult(
            pattern_id=pattern.id,
            pattern_name=pattern.name,
            severity=pattern.severity,
            tool_name=tool.name,
            status="warn",
            detail=f"Potential issues detected ({len(warn_indicators)} indicators)",
            evidence={"warnings": warn_indicators},
        )

    return TestResult(
        pattern_id=pattern.id,
        pattern_name=pattern.name,
        severity=pattern.severity,
        tool_name=tool.name,
        status="pass",
        detail="All payloads handled safely.",
    )


def _build_call_args(tool: ToolInfo, target_param: str, payload_value: str) -> dict[str, Any]:
    """Build arguments dict for a tool call, filling required params with defaults."""
    args: dict[str, Any] = {}
    for param in tool.parameters.values():
        if param.name == target_param:
            args[param.name] = payload_value
        elif param.required:
            # Fill with safe defaults based on type
            if param.type == "integer" or param.type == "number":
                args[param.name] = 0
            elif param.type == "boolean":
                args[param.name] = False
            else:
                args[param.name] = "test"
    return args


def _extract_response_text(resp: dict[str, Any]) -> str:
    """Extract readable text from an MCP tool call response."""
    result = resp.get("result", {})
    # MCP tool responses have content array
    content = result.get("content", [])
    if isinstance(content, list):
        texts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(item.get("text", ""))
        if texts:
            return "\n".join(texts)
    # Fallback: check for error
    error = resp.get("error", {})
    if error:
        return str(error.get("message", "")) + " " + str(error.get("data", ""))
    return str(result)


def _evaluate_response(response_text: str, pattern: Pattern, payload: Payload) -> str:
    """Evaluate a response against detection criteria. Returns 'pass', 'fail', or 'warn'."""
    response_lower = response_text.lower()

    # Check for positive detection indicators (signs of vulnerability)
    has_vuln_indicator = any(
        indicator.lower() in response_lower
        for indicator in pattern.detection.response_contains_any
    )

    # Check for negative indicators (signs the server handled it properly)
    has_safe_indicator = any(
        indicator.lower() in response_lower
        for indicator in pattern.detection.response_not_contains
    )

    if has_vuln_indicator and not has_safe_indicator:
        return "fail"
    elif has_vuln_indicator and has_safe_indicator:
        return "warn"
    else:
        return "pass"

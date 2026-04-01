"""JSON reporter for mcpfuzz scan results."""

from __future__ import annotations

import json
from pathlib import Path

from mcpfuzz.engine.runner import ScanReport


def generate_json(report: ScanReport) -> str:
    """Generate a JSON string from a scan report."""
    passed, total = report.score
    data = {
        "target": report.target,
        "timestamp": report.timestamp,
        "tools_discovered": report.tools_discovered,
        "results": [
            {
                "pattern": r.pattern_id,
                "pattern_name": r.pattern_name,
                "tool": r.tool_name,
                "severity": r.severity,
                "status": r.status,
                "detail": r.detail,
                "evidence": r.evidence,
            }
            for r in report.results
        ],
        "promises": {
            "detected": len(report.promise_analysis.promises),
            "claims": [
                {
                    "type": p.claim_type,
                    "source": p.source,
                    "text": p.text,
                    "tool": p.tool_name,
                }
                for p in report.promise_analysis.promises
            ],
            "broken": [
                {
                    "tool": r.tool_name,
                    "pattern": r.pattern_id,
                    "promise": r.evidence.get("broken_promise", {}),
                }
                for r in report.results
                if r.evidence.get("broken_promise")
            ],
        },
        "score": {
            "total": total,
            "passed": passed,
            "failed": report.failed,
            "warnings": report.warnings,
            "critical_fails": report.critical_fails,
        },
    }
    return json.dumps(data, indent=2)


def write_json(report: ScanReport, output_path: Path) -> None:
    """Write a JSON report to a file."""
    output_path.write_text(generate_json(report), encoding="utf-8")

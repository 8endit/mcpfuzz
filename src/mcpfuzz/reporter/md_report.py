"""Markdown reporter for mcpfuzz scan results."""

from __future__ import annotations

from pathlib import Path

from mcpfuzz.engine.runner import ScanReport


def generate_markdown(report: ScanReport) -> str:
    """Generate a Markdown report string."""
    passed, total = report.score
    lines = [
        "# mcpfuzz Security Report",
        "",
        f"- **Target**: {report.target}",
        f"- **Timestamp**: {report.timestamp}",
        f"- **Tools discovered**: {report.tools_discovered}",
        f"- **Score**: {passed}/{total} passed",
        "",
        "## Results",
        "",
        "| Severity | Pattern | Tool | Status | Detail |",
        "|----------|---------|------|--------|--------|",
    ]
    for r in report.results:
        lines.append(
            f"| {r.severity.upper()} | {r.pattern_name} | {r.tool_name} | {r.status.upper()} | {r.detail[:60]} |"
        )

    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Passed: {passed}")
    lines.append(f"- Failed: {report.failed}")
    lines.append(f"- Warnings: {report.warnings}")
    lines.append(f"- Critical failures: {report.critical_fails}")

    # Evidence for failures
    failures = [r for r in report.results if r.status == "fail"]
    if failures:
        lines.append("")
        lines.append("## Failure Details")
        for r in failures:
            lines.append("")
            lines.append(f"### {r.severity.upper()}: {r.pattern_name} on `{r.tool_name}`")
            lines.append("")
            lines.append(f"**Detail**: {r.detail}")
            if r.evidence:
                lines.append("")
                lines.append("**Evidence**:")
                for k, v in r.evidence.items():
                    val_str = str(v)[:200]
                    lines.append(f"- `{k}`: {val_str}")

    lines.append("")
    return "\n".join(lines)


def write_markdown(report: ScanReport, output_path: Path) -> None:
    """Write a Markdown report to a file."""
    output_path.write_text(generate_markdown(report), encoding="utf-8")

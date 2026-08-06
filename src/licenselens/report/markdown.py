"""Markdown summary writer."""

from __future__ import annotations

from pathlib import Path

from licenselens.models import ScanResult


def write_markdown_report(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = result.counts_by_status
    lines = [
        "# LicenseLens report",
        "",
        f"- **Version:** {result.version}",
        f"- **Scanned at:** {result.scanned_at}",
        f"- **Tenant:** {result.tenant_id or 'n/a (dry-run)'}",
        f"- **Owned capabilities:** {', '.join(result.owned_capabilities) or 'none'}",
        "",
        "## Summary",
        "",
    ]
    if counts:
        for status, n in sorted(counts.items()):
            lines.append(f"- `{status}`: {n}")
    else:
        lines.append("- No findings.")

    lines.extend(["", "## Findings", ""])
    for f in result.findings:
        lines.append(f"### {f.check_id} — {f.title}")
        lines.append("")
        lines.append(f"- **Status:** `{f.status.value}`")
        lines.append(f"- **Workload:** {f.workload.value}")
        lines.append(f"- **Severity:** {f.severity.value}")
        lines.append(f"- **Value impact:** {f.value_impact.value}")
        lines.append(f"- **Summary:** {f.summary}")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path

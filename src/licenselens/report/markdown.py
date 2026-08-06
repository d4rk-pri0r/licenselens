"""Markdown summary writer."""

from __future__ import annotations

from pathlib import Path

from licenselens.models import STATUS_PLAIN_LABELS, ScanResult


def write_markdown_report(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = result.counts_by_status
    lines = [
        f"# {result.tool_display_name} report",
        "",
        "A plain-language view of security capabilities you already pay for — "
        "and whether they are set up to help your organization.",
        "",
        f"- **Version:** {result.version}",
        f"- **Scanned at:** {result.scanned_at}",
        f"- **Tenant:** {result.tenant_id or 'n/a (dry-run)'}",
        "",
        "## At a glance",
        "",
    ]
    if counts:
        for status, n in sorted(counts.items()):
            label = STATUS_PLAIN_LABELS.get(status, status)
            lines.append(f"- **{label}** (`{status}`): {n}")
    else:
        lines.append("- No findings.")

    lines.extend(["", "## What you already pay for", ""])
    if result.capability_summaries:
        for cap in result.capability_summaries:
            lines.append(f"### {cap.plain_name}")
            lines.append("")
            lines.append(f"*Microsoft name: {cap.name}*")
            lines.append("")
            if cap.outcome:
                lines.append(f"- **What it does:** {cap.outcome}")
            if cap.why_it_matters:
                lines.append(f"- **Why it matters:** {cap.why_it_matters}")
            if cap.if_unused:
                lines.append(f"- **If unused:** {cap.if_unused}")
            lines.append("")
    else:
        lines.append("No licensed capabilities were resolved from entitlements.")
        lines.append("")

    lines.extend(["", "## Where you may not be getting the full benefit", ""])
    for f in result.findings:
        label = f.status_label or STATUS_PLAIN_LABELS.get(f.status.value, f.status.value)
        lines.append(f"### {f.display_customer_title}")
        lines.append("")
        lines.append(f"- **Status:** {label}")
        if f.customer_summary:
            lines.append(f"- **In plain English:** {f.customer_summary}")
        if f.customer_next_step:
            lines.append(f"- **Suggested next step:** {f.customer_next_step}")
        lines.append(f"- **Technical id:** `{f.check_id}`")
        lines.append("")

    if result.recommended_next_steps:
        lines.extend(["## Recommended first steps", ""])
        for i, step in enumerate(result.recommended_next_steps, start=1):
            lines.append(f"{i}. {step}")
        lines.append("")

    lines.extend(
        [
            "## Technical details",
            "",
            f"- Owned capability ids: {', '.join(result.owned_capabilities) or 'none'}",
            "",
        ]
    )
    for sku in result.subscribed_skus:
        plans = ", ".join(p.service_plan_name for p in sku.service_plans)
        lines.append(
            f"- SKU `{sku.sku_part_number}` "
            f"({sku.consumed_units or 0}/{sku.prepaid_units or '—'}): {plans}"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path

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
        f"- **Mode:** {result.scan_mode}" + (f" / {result.auth_mode}" if result.auth_mode else ""),
        f"- **Organization:** {result.tenant_display_name or result.tenant_id or 'n/a (dry-run)'}",
        "",
    ]
    if result.warnings:
        lines.extend(["## Notes", ""])
        for warning in result.warnings:
            lines.append(f"- {warning}")
        lines.append("")
    lines.extend(
        [
            "## At a glance",
            "",
        ]
    )
    rollup = result.capability_rollup
    lines.append(f"**{rollup.realized_sentence}.**")
    lines.append("")
    lines.append(f"- **Licensed capabilities detected:** {len(result.owned_capabilities)}")
    lines.append(
        f"- **Prioritized capabilities:** {rollup.you_own} "
        f"(priority packs: {', '.join(result.packs_scanned) or 'none'})"
    )
    lines.append(
        f"- **Fully working:** {rollup.fully_working} of {rollup.you_own} prioritized capabilities "
        f"({rollup.realized_percent}% realized)"
    )
    lines.append(
        f"- **Need attention:** {rollup.needs_attention + rollup.partly_set_up} "
        f"of {rollup.you_own} prioritized capabilities"
    )
    if result.has_exposed:
        exposed_titles = [
            finding.display_customer_title
            for finding in result.findings
            if finding.check_id in result.exposed_check_ids
        ]
        lines.append(f"- **High-risk priority (fix first):** {', '.join(exposed_titles)}")
    lines.append("")
    if result.moves:
        lines.extend(["### Top things to do first", ""])
        for i, move in enumerate(result.moves, start=1):
            effort = f" *({move.effort_label.lower()})*" if move.effort_label else ""
            lines.append(f"{i}. **{move.title}**{effort} — {move.why}")
            if move.customer_next_step:
                lines.append(f"   - Next step: {move.customer_next_step}")
        lines.append("")
        lines.append("*Effort is a rough guide, not a quote.*")
        lines.append("")
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
            lines.append(
                "- **Included through license SKU(s):** "
                f"{', '.join(cap.matched_skus) or 'Not reported'}"
            )
            lines.append(
                "- **Matching service plan(s):** "
                f"{', '.join(cap.matched_service_plans) or 'No matching service plan reported'}"
            )
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
        lines.append(f"- **Confidence:** {f.confidence_label or f.confidence.value}")
        lines.append(f"- **Data sources:** {', '.join(f.data_sources) or 'Not reported'}")
        lines.append(f"- **Limitations:** {'; '.join(f.limitations) or 'None reported'}")
        if f.deep_link:
            lines.append(f"- **Admin page:** [Open Microsoft admin page]({f.deep_link})")
        lines.append(f"- **Technical id:** `{f.check_id}`")
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

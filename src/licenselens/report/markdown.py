"""Markdown summary writer."""

from __future__ import annotations

from pathlib import Path

from licenselens.config_models import RedactionSettings
from licenselens.friendly_names import friendly_plan_name, friendly_sku_name
from licenselens.models import STATUS_PLAIN_LABELS, ScanResult
from licenselens.report.redaction import derive_redaction_targets, redact_text
from licenselens.report.viewmodel import human_copy


def write_markdown_report(
    result: ScanResult,
    path: Path,
    *,
    redaction: RedactionSettings | None = None,
) -> Path:
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
        f"- **Mode:** {human_copy('scan_mode', result.scan_mode)}"
        + (
            f" / {result.auth_mode}"
            if result.auth_mode and result.auth_mode != result.scan_mode
            else ""
        ),
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
    lines.append(f"**{rollup.realized_sentence.rstrip('.')}.**")
    lines.append("")
    activation_n = sum(1 for finding in result.findings if finding.tier.value != "hygiene")
    hygiene_n = sum(1 for finding in result.findings if finding.tier.value == "hygiene")
    lines.append(
        f"- **Activation assessment:** {activation_n} checks · "
        f"**Configuration hygiene (optional):** {hygiene_n} checks"
    )
    lines.append(f"- **Licensed capabilities detected:** {len(result.owned_capabilities)}")
    lines.append(
        f"- **Evaluated capabilities:** {rollup.you_own} "
        f"(priority packs: {', '.join(result.packs_scanned) or 'none'})"
    )
    lines.append(
        f"- **Met assessed criteria:** {rollup.fully_working} of {rollup.you_own} evaluated "
        f"capabilities ({rollup.realized_percent}% realized)"
    )
    if rollup.assessment_incomplete:
        lines.append(
            f"- **Assessment incomplete:** {rollup.assessment_incomplete} capabilities "
            "(error or skipped findings only — not counted in the realized %)"
        )
    lines.append(
        f"- **Need attention:** {rollup.needs_attention + rollup.partly_set_up} "
        f"of {rollup.you_own} evaluated capabilities"
    )
    if rollup.entitlement_unknown:
        lines.append(f"- **Entitlement unknown:** {rollup.entitlement_unknown} capabilities")
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
            if cap.entitlement_kind == "consumption":
                lines.append(
                    "- **Observed in Azure:** "
                    f"{', '.join(cap.observed_resources) or 'Azure resource'}"
                )
            else:
                sku_text = ", ".join(friendly_sku_name(name) for name in cap.matched_skus)
                lines.append(f"- **Included through license SKU(s):** {sku_text or 'Not reported'}")
                if cap.assigned_users is not None and cap.enabled_users:
                    prepaid = cap.prepaid_units if cap.prepaid_units is not None else "—"
                    lines.append(
                        f"- **Assignment:** Purchased {prepaid} · Assigned to "
                        f"{cap.assigned_users} of {cap.enabled_users} enabled users"
                    )
            plan_text = ", ".join(friendly_plan_name(name) for name in cap.matched_service_plans)
            lines.append(
                "- **Matching service plan(s):** "
                f"{plan_text or 'No matching service plan reported'}"
            )
            lines.append("")
    else:
        lines.append("No licensed capabilities were resolved from entitlements.")
        lines.append("")

    matrix = result.detection_realization or {}
    rows = matrix.get("rows") if isinstance(matrix, dict) else None
    if isinstance(rows, list) and rows:
        lines.extend(["", "## Detection realization", ""])
        lines.append(
            "Core tables expected for owned protections, whether they arrived "
            "in the last seven days, and whether a live analytics rule queries them."
        )
        lines.append("")
        lines.append(
            "| Capability | Table | Tier | Arriving? "
            "| Live rules (when assessed) | Connector hint |"
        )
        lines.append("|---|---|---|---|---:|---|")
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("ingesting") is None:
                arriving = "Not assessed"
            else:
                arriving = "Yes" if row.get("ingesting") else "No"
            watched = row.get("watched_by")
            watched_text = "Not assessed" if watched is None else str(watched)
            lines.append(
                f"| {row.get('capability_name', '')} | `{row.get('table', '')}` | "
                f"{row.get('tier', '')} | {arriving} | {watched_text} | "
                f"{row.get('connector_hint', '')} |"
            )
        dead = matrix.get("dead_rules") or []
        if dead:
            names = ", ".join(
                str(item.get("name") or "") for item in dead if isinstance(item, dict)
            )
            lines.append("")
            lines.append(f"Dead rules (query tables that are not arriving): {names}.")
        lines.append("")

    lines.extend(["", "## Where you may not be getting the full benefit", ""])
    activation = [f for f in result.findings if f.tier.value != "hygiene"]
    hygiene = [f for f in result.findings if f.tier.value == "hygiene"]
    for f in activation:
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
        limits = "; ".join(lim.rstrip(".") for lim in f.limitations)
        lines.append(f"- **Limitations:** {limits or 'None reported'}")
        if f.deep_link:
            lines.append(f"- **Admin page:** [Open Microsoft admin page]({f.deep_link})")
        lines.append(f"- **Technical id:** `{f.check_id}`")
        if f.pass_criteria is not None:
            lines.append("- **How this is decided:**")
            lines.append(f"  - OK: {f.pass_criteria.ok}")
            if f.pass_criteria.partial:
                lines.append(f"  - Partial: {f.pass_criteria.partial}")
            lines.append(f"  - Gap: {f.pass_criteria.gap}")
            if f.pass_criteria.evidence_fields:
                lines.append(
                    "  - Evidence fields: "
                    + ", ".join(f"`{name}`" for name in f.pass_criteria.evidence_fields)
                )
            if f.evaluator_ref:
                lines.append(f"  - Evaluator: `{f.evaluator_ref}`")
        lines.append("")

    if hygiene:
        lines.extend(["", "## Configuration hygiene (SCuBA-aligned, optional pack)", ""])
        for f in hygiene:
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

    lines.extend(
        [
            "## Technical details",
            "",
            f"- Owned capability ids: {', '.join(result.owned_capabilities) or 'none'}",
            "",
        ]
    )
    for sku in result.subscribed_skus:
        plans = ", ".join(friendly_plan_name(p.service_plan_name) for p in sku.service_plans)
        lines.append(
            f"- SKU {friendly_sku_name(sku.sku_part_number)} (`{sku.sku_part_number}`) "
            f"({sku.consumed_units or 0}/{sku.prepaid_units or '—'}): {plans}"
        )

    text = "\n".join(lines) + "\n"
    if redaction is not None:
        text = redact_text(
            text,
            targets=derive_redaction_targets(result),
            settings=redaction,
        )
    path.write_text(text, encoding="utf-8")
    return path

"""Static HTML dashboard writer."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from jinja2 import Environment, FileSystemLoader

from licenselens.models import (
    EXPOSURE_PLAIN_LABELS,
    TAGLINE,
    CapabilityOutcome,
    CapabilitySummary,
    ScanResult,
)
from licenselens.paths import templates_dir

_CAPABILITY_STATUS_RANK: dict[str, int] = {
    "needs_attention": 0,
    "partly_set_up": 1,
    "fully_working": 2,
    "not_licensed": 3,
}

_WORKLOAD_PRIORITY: Final = (
    "identity",
    "endpoint",
    "defender",
    "sentinel",
    "purview",
    "exchange",
    "collaboration",
    "teams",
    "power_platform",
    "power_bi",
    "intune",
    "azure",
)


@dataclass(frozen=True, slots=True)
class _CapabilityCard:
    """One ordered capability card — an HTML-only view model, never a model field."""

    summary: CapabilitySummary
    outcome: CapabilityOutcome | None
    status: str
    span: str
    workload: str | None


def _primary_workload(
    result: ScanResult, outcome: CapabilityOutcome | None
) -> str | None:
    """Pick the dominant related-finding workload for a capability header icon."""
    if outcome is None or not outcome.related_check_ids:
        return None
    related = set(outcome.related_check_ids)
    counts: Counter[str] = Counter()
    for finding in result.findings:
        if finding.check_id not in related:
            continue
        value = finding.workload.value
        if value != "general":
            counts[value] += 1
    if not counts:
        return None
    best = max(counts.values())
    candidates = {workload for workload, count in counts.items() if count == best}
    for workload in _WORKLOAD_PRIORITY:
        if workload in candidates:
            return workload
    return sorted(candidates)[0]


def _ordered_capability_cards(
    result: ScanResult, outcome_by_id: dict[str, CapabilityOutcome]
) -> list[_CapabilityCard]:
    """Build the HTML-only capability-card list without mutating ``ScanResult``.

    Span rule: ``needs_attention`` widens with the number of related checks
    (>=2 → 8/12, otherwise 6/12); every other status is a compact 4/12 card.
    """
    cards: list[_CapabilityCard] = []
    for summary in result.capability_summaries:
        outcome = outcome_by_id.get(summary.id)
        status = outcome.status if outcome else "not_licensed"
        related_count = len(outcome.related_check_ids) if outcome else 0
        if status == "needs_attention":
            span = "wide" if related_count >= 2 else "medium"
        else:
            span = "compact"
        cards.append(
            _CapabilityCard(
                summary,
                outcome,
                status,
                span,
                _primary_workload(result, outcome),
            )
        )
    cards.sort(
        key=lambda card: (
            _CAPABILITY_STATUS_RANK.get(card.status, len(_CAPABILITY_STATUS_RANK)),
            card.summary.plain_name.lower(),
        )
    )
    return cards


def report_environment() -> Environment:
    """Return the shared report Jinja environment (autoescape on, templates dir)."""
    return Environment(
        loader=FileSystemLoader(str(templates_dir())),
        autoescape=True,
    )


def build_report_context(result: ScanResult) -> dict[str, object]:
    """Build the render context shared by the legacy and bundle entry templates."""
    outcome_by_id = {o.id: o for o in result.capability_outcomes}
    return {
        "result": result,
        "tagline": TAGLINE,
        "counts": result.counts_by_status,
        "findings": result.findings,
        "status_order": ["gap", "partial", "ok", "not_licensed", "skipped", "error"],
        "exposure_labels": EXPOSURE_PLAIN_LABELS,
        "capability_cards": _ordered_capability_cards(result, outcome_by_id),
    }


def write_html_report(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    html = (
        report_environment().get_template("report.html.j2").render(**build_report_context(result))
    )
    path.write_text(html, encoding="utf-8")
    return path

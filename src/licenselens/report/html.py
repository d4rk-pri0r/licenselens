"""Static HTML dashboard writer."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from licenselens.models import (
    CAPABILITY_STATUS_LABELS,
    EXPOSURE_PLAIN_LABELS,
    STATUS_PLAIN_LABELS,
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


@dataclass(frozen=True, slots=True)
class _CapabilityCard:
    """One ordered capability card — an HTML-only view model, never a model field."""

    summary: CapabilitySummary
    outcome: CapabilityOutcome | None
    status: str
    span: str


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
        cards.append(_CapabilityCard(summary, outcome, status, span))
    cards.sort(
        key=lambda card: (
            _CAPABILITY_STATUS_RANK.get(card.status, len(_CAPABILITY_STATUS_RANK)),
            card.summary.plain_name.lower(),
        )
    )
    return cards


def write_html_report(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(templates_dir())),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    outcome_by_id = {o.id: o for o in result.capability_outcomes}
    html = template.render(
        result=result,
        tagline=TAGLINE,
        counts=result.counts_by_status,
        findings=result.findings,
        status_labels=STATUS_PLAIN_LABELS,
        status_order=["gap", "partial", "ok", "not_licensed", "skipped", "error"],
        outcome_by_id=outcome_by_id,
        capability_status_labels=CAPABILITY_STATUS_LABELS,
        exposure_labels=EXPOSURE_PLAIN_LABELS,
        capability_cards=_ordered_capability_cards(result, outcome_by_id),
    )
    path.write_text(html, encoding="utf-8")
    return path

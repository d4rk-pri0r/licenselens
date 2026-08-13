"""Static HTML dashboard writer."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from licenselens.models import (
    CAPABILITY_STATUS_LABELS,
    EXPOSURE_PLAIN_LABELS,
    STATUS_PLAIN_LABELS,
    TAGLINE,
    ScanResult,
)
from licenselens.paths import templates_dir


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
    )
    path.write_text(html, encoding="utf-8")
    return path

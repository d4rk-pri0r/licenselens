"""Static HTML dashboard writer."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from licenselens.models import STATUS_PLAIN_LABELS, ScanResult
from licenselens.paths import templates_dir


def write_html_report(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(templates_dir())),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    html = template.render(
        result=result,
        counts=result.counts_by_status,
        findings=result.findings,
        status_labels=STATUS_PLAIN_LABELS,
        status_order=["gap", "partial", "ok", "not_licensed", "skipped", "error"],
    )
    path.write_text(html, encoding="utf-8")
    return path

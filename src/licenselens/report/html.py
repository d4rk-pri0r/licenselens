"""Static HTML dashboard writer."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from licenselens.models import (
    EXPOSURE_PLAIN_LABELS,
    TAGLINE,
    ScanResult,
)
from licenselens.paths import templates_dir
from licenselens.report.icons import workload_svg_map
from licenselens.report.viewmodel import build_constellation, build_opening, build_sections


def report_environment() -> Environment:
    """Return the shared report Jinja environment (autoescape on, templates dir)."""
    return Environment(
        loader=FileSystemLoader(str(templates_dir())),
        autoescape=True,
    )


def build_report_context(result: ScanResult) -> dict[str, object]:
    """Build the render context shared by the legacy and bundle entry templates.

    Delegates all view-model work to :mod:`licenselens.report.viewmodel`; this
    function only assembles the flat keys the templates (and the bundle) consume.
    """
    sections = build_sections(result)
    return {
        "result": result,
        "tagline": TAGLINE,
        "sections": sections,
        "opening": build_opening(result),
        "constellation": build_constellation(result),
        "moves": sections["C"],
        "findings": sections["E"]["findings"],
        "blocks": sections["D"],
        "capabilities": sections["B"],
        "posture": sections["A"]["posture"],
        "rollup": sections["A"]["rollup"],
        "counts": result.counts_by_status,
        "status_order": ["gap", "partial", "ok", "not_licensed", "skipped", "error"],
        "exposure_labels": EXPOSURE_PLAIN_LABELS,
    }


def write_html_report(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    context = build_report_context(result)
    context["workload_svg_map"] = workload_svg_map()
    html = report_environment().get_template("report.html.j2").render(**context)
    path.write_text(html, encoding="utf-8")
    return path

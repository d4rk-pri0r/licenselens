"""Static HTML dashboard writer."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from licenselens.catalog.expected_states import expected_state_map
from licenselens.config_models import RedactionSettings
from licenselens.models import (
    EXPOSURE_PLAIN_LABELS,
    TAGLINE,
    ScanResult,
)
from licenselens.paths import templates_dir
from licenselens.report.icons import workload_svg_map
from licenselens.report.redaction import derive_redaction_targets, redact_text
from licenselens.report.viewmodel import (
    EXEC_COPY,
    build_constellation,
    build_opening,
    build_provenance,
    build_sections,
)


def report_environment() -> Environment:
    """Return the shared report Jinja environment (autoescape on, templates dir)."""
    return Environment(
        loader=FileSystemLoader(str(templates_dir())),
        autoescape=True,
    )


def build_report_context(
    result: ScanResult,
    expected_by_check_id: dict[str, str] | None = None,
) -> dict[str, object]:
    """Build the render context shared by the legacy and bundle entry templates.

    Delegates all view-model work to :mod:`licenselens.report.viewmodel`; this
    function only assembles the flat keys the templates (and the bundle) consume.
    ``expected_by_check_id`` threads the catalog ``check_id -> expected_state``
    mapping into the D-section belief blocks; when omitted the view model
    resolves it once itself.
    """
    sections = build_sections(result, expected_by_check_id)
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
        "exec_copy": EXEC_COPY,
        "provenance": build_provenance(result),
    }


def write_html_report(
    result: ScanResult,
    path: Path,
    *,
    redaction: RedactionSettings | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    context = build_report_context(result, expected_state_map())
    context["workload_svg_map"] = workload_svg_map()
    html = report_environment().get_template("report.html.j2").render(**context)
    if redaction is not None:
        html = redact_text(
            html,
            targets=derive_redaction_targets(result),
            settings=redaction,
        )
    path.write_text(html, encoding="utf-8")
    return path

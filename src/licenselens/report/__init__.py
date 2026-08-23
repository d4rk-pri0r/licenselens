"""Report writers (HTML, JSON, Markdown, bundle, action plan)."""

from licenselens.report.action_plan import write_action_plan
from licenselens.report.bundle import (
    ReportBundleError,
    build_report_bundle,
    extract_report_archive,
    verify_report_bundle,
)
from licenselens.report.html import write_html_report
from licenselens.report.json_report import write_json_report
from licenselens.report.markdown import write_markdown_report

__all__ = [
    "write_html_report",
    "write_json_report",
    "write_markdown_report",
    "write_action_plan",
    "build_report_bundle",
    "verify_report_bundle",
    "extract_report_archive",
    "ReportBundleError",
]

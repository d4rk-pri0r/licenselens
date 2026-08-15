"""Structural hardening contracts for the offline report (Todo 28).

These tests lock the *static* security and compatibility properties of the
versioned report app bundle without a browser:

* a Content-Security-Policy delivered via a ``<meta>`` element that blocks
  inline/``eval`` scripts and network while allowing the local hashed assets;
* no inline event handlers and no ``eval``/``Function`` constructor anywhere in
  the app JavaScript;
* no ``http://``/``https://`` reference in the CSS or JavaScript assets;
* RTL-safe logical layout (``*-inline-*`` properties, ``text-align: start``);
* byte-identical CSP output across rebuilds; and
* the legacy JSON/report writers remaining functional alongside the bundle.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

import html5lib

from licenselens.paths import templates_dir
from licenselens.report.bundle import DATA_JS_GLOBAL, build_report_bundle
from licenselens.report.html import write_html_report
from licenselens.report.json_report import write_json_report
from tests.report_fixtures import comprehensive_report

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CSP_REQUIRED = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
]

CSP_FORBIDDEN = [
    "'unsafe-eval'",
    "script-src 'self' 'unsafe-inline'",
    "script-src *",
    "'unsafe-inline' 'unsafe-eval'",
]


def _entry_html(tmp_path: Path) -> str:
    bundle = build_report_bundle(comprehensive_report(), tmp_path / "bundle")
    return bundle.entry_path.read_text(encoding="utf-8")


def _csp_content(html: str) -> str:
    match = re.search(
        r'<meta[^>]+http-equiv=["\']?Content-Security-Policy["\']?[^>]*content="([^"]+)"',
        html,
    )
    assert match, "CSP meta element missing from the bundle entry"
    return match.group(1)


def _parse_html(html: str) -> ET.Element:
    tree = html5lib.parse(html, treebuilder="etree", namespaceHTMLElements=False)
    return tree.getroot() if hasattr(tree, "getroot") else tree  # type: ignore[return-value]


def _app_asset(logical_name: str) -> str:
    return (templates_dir() / f"report_app/v2/{logical_name}").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Content-Security-Policy
# ---------------------------------------------------------------------------


def test_csp_meta_present_with_required_directives(tmp_path: Path) -> None:
    csp = _csp_content(_entry_html(tmp_path))
    for directive in CSP_REQUIRED:
        assert directive in csp, f"CSP missing required directive {directive!r}: {csp}"


def test_csp_forbids_unsafe_eval_and_inline_script(tmp_path: Path) -> None:
    csp = _csp_content(_entry_html(tmp_path))
    for forbidden in CSP_FORBIDDEN:
        assert forbidden not in csp, f"CSP must not contain {forbidden!r}: {csp}"


def test_csp_is_deterministic_across_rebuilds(tmp_path: Path) -> None:
    first = _csp_content(_entry_html(tmp_path))
    second = _csp_content(_entry_html(tmp_path))
    assert first == second, "CSP meta content diverged between rebuilds"


# ---------------------------------------------------------------------------
# No inline event handlers / eval
# ---------------------------------------------------------------------------


def test_no_inline_event_handlers_in_entry(tmp_path: Path) -> None:
    root = _parse_html(_entry_html(tmp_path))
    offenders = []
    for element in root.iter():
        for attr in element.attrib:
            if attr.lower().startswith("on"):
                offenders.append((element.tag, attr))
    assert not offenders, f"inline event handler attributes found: {offenders}"


def test_no_eval_or_function_constructor_in_app_js() -> None:
    js = _app_asset("app.js")
    for forbidden in (
        "eval(",
        "new Function",
        "Function(",
        'setTimeout("',
        "setTimeout('",
        'setInterval("',
        "setInterval('",
    ):
        assert forbidden not in js, f"app.js contains forbidden runtime primitive {forbidden!r}"


def test_no_inline_event_handler_assignment_in_app_js() -> None:
    js = _app_asset("app.js")
    for forbidden in (
        ".onclick",
        ".onerror",
        ".onload",
        ".onchange",
        ".onkeydown",
        ".onkeyup",
        ".onmouseover",
        ".onfocus",
    ):
        assert forbidden not in js, f"app.js assigns an inline handler via {forbidden!r}"


def test_app_js_binds_events_via_add_event_listener() -> None:
    js = _app_asset("app.js")
    assert "addEventListener" in js, "app.js must bind events via addEventListener"


# ---------------------------------------------------------------------------
# No external network references in CSS/JS assets
# ---------------------------------------------------------------------------


def test_css_and_js_assets_have_no_http_references() -> None:
    for logical_name in ("app.css", "app.js"):
        content = _app_asset(logical_name).lower()
        assert "http://" not in content, f"{logical_name} contains http://"
        assert "https://" not in content, f"{logical_name} contains https://"
        assert "@import" not in content, f"{logical_name} contains CSS @import"
        assert "fetch(" not in content, f"{logical_name} contains fetch("
        assert "xmlhttprequest" not in content, f"{logical_name} contains XMLHttpRequest"


# ---------------------------------------------------------------------------
# RTL-safe logical layout
# ---------------------------------------------------------------------------


def test_app_css_uses_logical_directional_properties() -> None:
    css = _app_asset("app.css")
    for logical in (
        "border-inline-start",
        "padding-inline-start",
        "margin-inline-start",
        "margin-inline-end",
        "text-align: start",
        "text-align: end",
    ):
        assert logical in css, f"app.css missing logical property {logical!r}"


def test_app_css_has_no_physical_directional_layout_properties() -> None:
    css = _app_asset("app.css")
    # The sr-only clip and logo centering legitimately use physical coordinates;
    # every *layout* directional property must be logical. Strip those known-safe
    # uses before asserting the rest are absent.
    for physical in (
        "border-left",
        "border-right",
        "padding-left",
        "padding-right",
        "margin-left",
        "margin-right",
        "text-align: left",
        "text-align: right",
    ):
        assert physical not in css, f"app.css retains physical directional property {physical!r}"


# ---------------------------------------------------------------------------
# Legacy JSON / report paths remain functional
# ---------------------------------------------------------------------------


def test_legacy_html_and_json_writers_still_work_alongside_bundle(tmp_path: Path) -> None:
    result = comprehensive_report()

    html_out = write_html_report(result, tmp_path / "legacy.html")
    assert html_out.is_file()
    legacy_html = html_out.read_text(encoding="utf-8")
    assert "Where you stand" in legacy_html

    json_out = write_json_report(result, tmp_path / "legacy.json")
    assert json_out.is_file()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert {f["status"] for f in data["findings"]} == {
        "gap",
        "partial",
        "ok",
        "not_licensed",
        "skipped",
        "error",
    }


def test_bundle_data_asset_is_escaped_and_global_named(tmp_path: Path) -> None:
    bundle = build_report_bundle(comprehensive_report(), tmp_path / "bundle")
    data_files = list(bundle.assets_dir.glob("report-data-*.js"))
    assert len(data_files) == 1
    data = data_files[0].read_text(encoding="utf-8")
    assert "window.LICENSELENS_WORKLOAD_ICONS = " in data
    assert f"{DATA_JS_GLOBAL} = " in data
    assert "<script>alert(1)</script>" not in data
    assert "</script" not in data.lower()

"""Browser hardening contracts for the offline report app (Todo 28).

These tests drive the real ``file://`` bundle through Chromium and lock the
runtime security, accessibility, and compatibility properties:

* the CSP meta actually blocks injected inline scripts and ``eval`` while the
  local hashed assets still load;
* forced-colors, 200%/400% zoom reflow, and RTL logical layout hold without
  overflow or contrast collapse;
* keyboard focus and disclosure behavior remain native;
* the four named negative regressions — external request, eval, overflow, and
  contrast — each trigger a dedicated test that proves the defense/detector.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page

from licenselens.models import (
    BlastRadius,
    Confidence,
    Effort,
    Finding,
    FindingStatus,
    ScanResult,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.report.bundle import build_report_bundle
from licenselens.schema_contracts import EvaluationMode
from tests.report_fixtures import empty_report
from tests.wcag import contrast_ratio

pytestmark = pytest.mark.browser

SCANNED_AT = "2026-01-15T09:30:00+00:00"

_RGB_RE = re.compile(r"rgba?\((\d+),\s*(\d+),\s*(\d+)")


def _finding(check_id: str, status: str, severity: str, confidence: str, workload: str) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"{check_id} control",
        workload=Workload(workload),
        status=FindingStatus(status),
        severity=Severity(severity),
        value_impact=ValueImpact.HIGH,
        impact=ValueImpact.HIGH,
        effort=Effort.HOURS,
        blast_radius=BlastRadius.ALL_USERS,
        summary=f"{check_id}: {status} observed.",
        customer_title=f"{check_id} control",
        customer_summary=f"{check_id} customer summary.",
        customer_next_step=f"Fix {check_id}.",
        confidence=Confidence(confidence),
        confidence_label=f"{confidence} confidence",
        evaluation_mode=EvaluationMode.DIRECT,
        data_sources=["microsoft.graph"],
        limitations=["First limitation"],
    )


def hardening_report() -> ScanResult:
    findings = [
        _finding("a-gap", "gap", "high", "high", "identity"),
        _finding("b-partial", "partial", "high", "low", "endpoint"),
        _finding("c-ok", "ok", "low", "high", "defender"),
        _finding("d-notlic", "not_licensed", "info", "medium", "sentinel"),
        _finding("e-skip", "skipped", "medium", "low", "purview"),
        _finding("f-error", "error", "high", "medium", "identity"),
    ]
    return ScanResult(
        version="0.3.0",
        tenant_display_name="Contoso Demo Tenant",
        scan_mode="dry_run",
        scanned_at=SCANNED_AT,
        findings=findings,
        packs_scanned=["identity", "endpoint"],
    )


@pytest.fixture
def app_uri(tmp_path: Path):
    def _build(result: ScanResult, name: str = "bundle") -> tuple[str, Path]:
        bundle = build_report_bundle(result, tmp_path / name)
        return bundle.entry_path.as_uri(), bundle.root

    return _build


def _parse_rgb(value: str) -> tuple[int, int, int] | None:
    match = _RGB_RE.search(value)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _to_hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def _effective_fg_bg(page: Page, selector: str) -> tuple[str, str]:
    """Return (fg_hex, bg_hex) for ``selector``, resolving transparent ancestors."""
    colors = page.evaluate(
        """(sel) => {
            const el = document.querySelector(sel);
            if (!el) return null;
            const parse = (s) => {
                const m = s.match(/rgba?\\((\\d+),\\s*(\\d+),\\s*(\\d+)/);
                return m ? [+m[1], +m[2], +m[3]] : null;
            };
            const fg = parse(getComputedStyle(el).color);
            let node = el;
            let bg = null;
            while (node && !bg) {
                const parsed = parse(getComputedStyle(node).backgroundColor);
                const alpha = getComputedStyle(node).backgroundColor;
                if (parsed && (!alpha.includes('rgba') || !alpha.includes(', 0)'))) bg = parsed;
                node = node.parentElement;
            }
            return { fg: fg, bg: bg };
        }""",
        selector,
    )
    assert colors and colors["fg"] and colors["bg"], f"could not resolve colors for {selector}"
    return _to_hex(tuple(colors["fg"])), _to_hex(tuple(colors["bg"]))


def _no_horizontal_overflow(page: Page) -> dict[str, int]:
    return page.evaluate(
        "() => ({ sw: document.documentElement.scrollWidth,"
        " cw: document.documentElement.clientWidth })"
    )


# ---------------------------------------------------------------------------
# CSP: blocks injected scripts, allows local assets
# ---------------------------------------------------------------------------


def test_csp_meta_is_active_in_dom(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    csp = page.evaluate(
        "() => document.querySelector("
        "'meta[http-equiv=\"Content-Security-Policy\"]')?.content || null"
    )
    assert csp, "CSP meta missing from the rendered bundle"
    assert "script-src 'self'" in csp
    assert "'unsafe-eval'" not in csp


def test_csp_allows_local_assets_and_app_boots(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    page.wait_for_load_state("load")
    assert page.locator(".finding").count() == 6
    assert page.evaluate("() => document.styleSheets.length") >= 1
    assert page.evaluate("() => Array.isArray(window.LICENSELENS_REPORT_JSON.findings)")


def test_no_inline_event_handlers_in_dom(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    offenders = page.evaluate(
        """() => Array.from(document.querySelectorAll('*'))
            .flatMap(el => Array.from(el.attributes).map(a => a.name))
            .filter(n => n.toLowerCase().startsWith('on'))"""
    )
    assert offenders == [], f"inline event handler attributes in DOM: {offenders}"


# ---------------------------------------------------------------------------
# Forced colors, zoom reflow, RTL
# ---------------------------------------------------------------------------


def test_forced_colors_keep_text_high_contrast(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.emulate_media(forced_colors="active")
    page.goto(uri)
    page.evaluate("() => document.querySelectorAll('details').forEach(d => d.open = true)")
    body_fg, body_bg = _effective_fg_bg(page, "body")
    assert contrast_ratio(body_fg, body_bg) >= 4.5, (
        f"forced-colors body contrast: {body_fg}/{body_bg}"
    )

    marker = page.evaluate(
        "() => getComputedStyle(document.querySelector('.finding.gap .status-marker')).color"
    )
    body_color = page.evaluate("() => getComputedStyle(document.body).color")
    # Under forced colors the gap marker must adopt CanvasText (same ink as the
    # body text) rather than the low-contrast brand action color.
    assert marker == body_color, f"forced-colors status marker drifted from CanvasText: {marker}"
    assert marker != "rgb(255, 115, 122)", "status marker kept the low-contrast brand action ink"


@pytest.mark.parametrize("width", [640, 320], ids=["200-percent", "400-percent"])
def test_reflow_no_overflow_at_zoom(app_uri: str, page: Page, width: int) -> None:
    # WCAG 1.4.10 reflow: 200% zoom of a 1280px viewport == 640 CSS px, 400% == 320.
    uri, _ = app_uri(hardening_report())
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(uri)
    page.evaluate("() => document.querySelectorAll('details').forEach(d => d.open = true)")
    metrics = _no_horizontal_overflow(page)
    assert metrics["sw"] <= metrics["cw"], f"horizontal overflow at {width}px: {metrics}"


def test_rtl_logical_layout_mirrors_without_overflow(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    page.evaluate("() => document.documentElement.setAttribute('dir', 'rtl')")
    page.wait_for_timeout(100)
    metrics = _no_horizontal_overflow(page)
    assert metrics["sw"] <= metrics["cw"], f"RTL horizontal overflow: {metrics}"

    border = page.evaluate(
        """() => { const el = document.querySelector('.finding.gap');
            const s = getComputedStyle(el);
            return {
                inlineStart: s.borderInlineStartWidth,
                left: s.borderLeftWidth,
                right: s.borderRightWidth
            }; }"""
    )
    assert border["inlineStart"] == "3px"
    assert border["right"] == "3px" and border["left"] == "0px", f"accent not mirrored: {border}"


# ---------------------------------------------------------------------------
# Screen + print contrast, keyboard disclosure
# ---------------------------------------------------------------------------


def test_screen_body_and_status_contrast_meet_wcag_aa(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    body_fg, body_bg = _effective_fg_bg(page, "body")
    assert contrast_ratio(body_fg, body_bg) >= 4.5, f"body contrast {body_fg}/{body_bg}"

    marker_fg, marker_bg = _effective_fg_bg(page, ".finding.gap .status-marker")
    assert contrast_ratio(marker_fg, marker_bg) >= 4.5, (
        f"gap status marker contrast {marker_fg}/{marker_bg}"
    )


def test_print_emulation_renders_complete_unpaginated_findings(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.emulate_media(media="print")
    page.goto(uri)
    assert page.locator("[data-print-list] .print-finding").count() == 6
    assert (
        page.locator("[data-print-list]").evaluate("el => getComputedStyle(el).display") == "block"
    )
    metrics = _no_horizontal_overflow(page)
    assert metrics["sw"] <= metrics["cw"], f"print horizontal overflow: {metrics}"


def test_no_img_and_workload_text_labels(app_uri: str, page: Page) -> None:
    """v2 retires the v1 ``<img>`` workload-icon allowlist; workloads are text-only."""
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    page.wait_for_load_state("load")

    # The strongest form of the v1 "icons are decorative/restrained" guard:
    # v2 renders no <img> at all, so there is nothing to hide, brand, or misuse.
    assert page.locator("img").count() == 0, "v2 must not render any <img> element"

    nav_text = page.locator("nav.workload-nav").inner_text()
    assert "Identity" in nav_text, "workload nav missing visible text labels"


def test_evidence_drawer_keyboard_operable(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    details = page.locator(".finding").first.locator("details.tech")
    summary = details.locator("summary")
    summary.focus()
    assert summary.evaluate("el => el.matches(':focus')")
    page.keyboard.press("Enter")
    assert details.evaluate("el => el.open") is True
    page.keyboard.press("Space")
    assert details.evaluate("el => el.open") is False


# ---------------------------------------------------------------------------
# Named negative regressions: each class triggers a dedicated test
# ---------------------------------------------------------------------------


def test_negative_inline_script_is_blocked_by_csp(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    page.evaluate(
        "() => { const s = document.createElement('script');"
        " s.textContent = 'window.__inlinePwned = true'; document.body.appendChild(s); }"
    )
    page.wait_for_timeout(200)
    assert page.evaluate("() => window.__inlinePwned") is None, (
        "injected inline script executed despite CSP"
    )


def test_negative_eval_is_blocked_by_csp(app_uri: str, page: Page) -> None:
    uri, root = app_uri(hardening_report())
    (root / "eval-probe.js").write_text(
        "window.__evalResult = 'ran'; try { window.__evalResult = eval('1+1'); }"
        " catch (e) { window.__evalBlocked = true; }",
        encoding="utf-8",
    )
    page.goto(uri)
    page.add_script_tag(url=(root / "eval-probe.js").as_uri())
    page.wait_for_timeout(200)
    assert page.evaluate("() => window.__evalBlocked") is True, "eval() was not blocked by CSP"


def test_negative_external_request_is_blocked(app_uri: str, page: Page) -> None:
    uri, _ = app_uri(hardening_report())
    page.goto(uri)
    responses: list[str] = []
    page.on("response", lambda r: responses.append(r.url))
    page.evaluate(
        "() => {"
        " const img = document.createElement('img'); img.src = 'https://example.com/x.png';"
        " document.body.appendChild(img);"
        " const s = document.createElement('script'); s.src = 'https://example.com/x.js';"
        " document.body.appendChild(s); }"
    )
    page.wait_for_timeout(500)
    external = [url for url in responses if url.startswith(("http://", "https://"))]
    assert external == [], f"external resource actually loaded: {external}"


def test_negative_overflow_regression_is_detected(app_uri: str, page: Page) -> None:
    # A detector helper must flag a deliberately overflowing page, proving the
    # same check used across the suite would catch a real layout regression.
    uri, _ = app_uri(empty_report())
    page.goto(uri)
    page.evaluate(
        "() => { const d = document.createElement('div');"
        " d.style.cssText = 'position:absolute; left:0; top:0; width:5000px; height:1px;';"
        " document.body.appendChild(d); }"
    )
    metrics = _no_horizontal_overflow(page)
    assert metrics["sw"] > metrics["cw"], "overflow detector failed to flag a wide element"


def test_negative_contrast_regression_is_detected() -> None:
    # The screen brand-action ink is not print-safe on white; the detector must
    # reject it below AA while the print inks pass (locks the print override).
    assert contrast_ratio("#ff737a", "#ffffff") < 4.5, "brand action ink unexpectedly AA on white"
    for ink in ("#b3261e", "#8a5a00", "#1e7a3a", "#57534e"):
        assert contrast_ratio(ink, "#ffffff") >= 4.5, f"print ink {ink} fell below 4.5:1"

"""Persistent Chromium browser contracts for the Security License Lens HTML report.

The report is a single self-contained offline file opened via ``file://``, so these
tests render the real artifact through ``write_html_report`` and navigate with
``Path.as_uri()`` — never a dev server, never an external request.

Two groups, deliberately partitioned:

* **ESTABLISHED INVARIANTS — must PASS today**: regression guards locking the
  current offline/disclosure/section/overflow behavior. This includes the former
  "RED redesign contracts" — the redesign has since landed, so those contracts
  are now green invariants and are reclassified here.
* **FIXTURE INTEGRITY**: one test guarantees the browser-safe fixture never
  renders a raw ``<script>`` payload and still covers every status/exposure/move
  variant.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from playwright.sync_api import Page

from licenselens.models import ScanResult
from licenselens.report.html import write_html_report
from tests.report_fixtures import comprehensive_report

pytestmark = pytest.mark.browser

VIEWPORTS = [(375, 812), (768, 1024), (1024, 768), (1280, 900), (1440, 1000)]

SECTION_HEADINGS = [
    "Security posture",
    "Licensed control inventory",
    "Priority actions",
    "Assessment findings",
]

ALL_FINDING_STATUSES = {"gap", "partial", "ok", "not_licensed", "skipped", "error"}

BROWSER_SAFE_WARNING = "Ampersand & less-than < angle > quotes \" ' and slashes / are escaped."

_OPEN_DISCLOSURES_JS = "() => document.querySelectorAll('details').forEach(d => { d.open = true; })"

_SCROLL_METRICS_JS = (
    "() => ({ scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth })"
)

_FOCUS_OUTLINE_JS = (
    "el => { const s = getComputedStyle(el);"
    " return { style: s.outlineStyle, width: s.outlineWidth }; }"
)

# Composite an element's computed text/background color over the printed white page
# in the browser (canvas), returning clean [r, g, b] triples the Python side can feed
# straight into the WCAG formula. This sidesteps color-mix()/color(srgb …) serialization.
_PRINT_COLORS_JS = """el => {
    const s = getComputedStyle(el);
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 1;
    const ctx = canvas.getContext('2d');
    const pixel = (color) => {
        ctx.clearRect(0, 0, 1, 1);
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, 1, 1);
        ctx.fillStyle = color;
        ctx.fillRect(0, 0, 1, 1);
        const d = ctx.getImageData(0, 0, 1, 1).data;
        return [d[0], d[1], d[2]];
    };
    return { fg: pixel(s.color), bg: pixel(s.backgroundColor) };
}"""


def browser_safe_report() -> ScanResult:
    """``comprehensive_report()`` with the ``<script>`` payload replaced by a
    browser-safe metacharacter string — never render a raw ``<script>`` into Chromium."""
    result = comprehensive_report()
    warnings = [
        BROWSER_SAFE_WARNING if "<script>" in warning else warning for warning in result.warnings
    ]
    name = (
        result.tenant_display_name.replace("<script>alert(1)</script>", "Contoso Demo Tenant")
        if result.tenant_display_name
        else None
    )
    return result.model_copy(update={"warnings": warnings, "tenant_display_name": name})


@pytest.fixture
def report_uri(tmp_path: Path) -> str:
    """Render the browser-safe fixture to a tmp file and return its ``file://`` URI."""
    out = write_html_report(browser_safe_report(), tmp_path / "report.html")
    return out.as_uri()


def _open_all_disclosures(page: Page) -> None:
    """Open every native ``<details>`` so the tables/links they contain are laid out."""
    page.evaluate(_OPEN_DISCLOSURES_JS)


def _relative_luminance(r: float, g: float, b: float) -> float:
    def channel(value: float) -> float:
        value /= 255.0
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def _contrast_ratio(rgb1: tuple[float, float, float], rgb2: tuple[float, float, float]) -> float:
    first = _relative_luminance(*rgb1)
    second = _relative_luminance(*rgb2)
    lighter, darker = (first, second) if first >= second else (second, first)
    return (lighter + 0.05) / (darker + 0.05)


# ---------------------------------------------------------------------------
# FIXTURE INTEGRITY (must stay green — guards the "no raw <script>" guarantee)
# ---------------------------------------------------------------------------


def test_browser_safe_fixture_has_no_script_payload(tmp_path: Path) -> None:
    result = browser_safe_report()
    assert {f.status.value for f in result.findings} == ALL_FINDING_STATUSES
    assert result.has_exposed is True
    assert len(result.moves) == 3
    assert not any("<script>" in warning for warning in result.warnings)
    assert "<script>" not in (result.tenant_display_name or "")
    html = write_html_report(result, tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)" not in html, "raw injected <script> payload reached the report"


# ---------------------------------------------------------------------------
# GROUP A — established browser invariants (offline, overflow, a11y, print)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("width,height", VIEWPORTS)
def test_no_horizontal_overflow(page: Page, report_uri: str, width: int, height: int) -> None:
    page.set_viewport_size({"width": width, "height": height})
    page.goto(report_uri)
    _open_all_disclosures(page)
    metrics = page.evaluate(_SCROLL_METRICS_JS)
    # Primary content must never push the document wider than the viewport. A table
    # may still scroll internally, but only inside an explicit data-table-scroll wrapper
    # (which does not expand document.documentElement.scrollWidth).
    assert metrics["scrollWidth"] <= metrics["innerWidth"], (
        f"horizontal document overflow at {width}px: scrollWidth={metrics['scrollWidth']}"
        f" > innerWidth={metrics['innerWidth']}"
    )


def test_filter_keyboard_and_aria_pressed(page: Page, report_uri: str) -> None:
    page.goto(report_uri)
    buttons = page.locator("button[data-filter], button[data-workload]")
    assert buttons.count() > 0, "no filter controls found"

    # Invariant: every filter button must expose aria-pressed="true"|"false".
    for index in range(buttons.count()):
        button = buttons.nth(index)
        pressed = button.get_attribute("aria-pressed")
        assert pressed in ("true", "false"), (
            f"filter button missing aria-pressed='true'|'false' (got {pressed!r})"
        )

    # Keyboard operability: Enter/Space toggle the filter and update the visible count.
    page.locator("button[data-filter='gap']").focus()
    page.keyboard.press("Enter")
    assert page.locator(".filter-count").inner_text().strip() == "Showing 1 of 6"

    page.locator("button[data-workload='endpoint']").focus()
    page.keyboard.press("Space")
    assert page.locator(".filter-count").inner_text().strip() == "Showing 0 of 6"


def test_live_count_region(page: Page, report_uri: str) -> None:
    page.goto(report_uri)
    region = page.locator('[role="status"]')
    assert region.count() > 0, "missing results-count region with role=status"
    assert region.first.get_attribute("aria-live"), "count region missing aria-live"


def test_focus_outline_visible_on_keyboard_focus(page: Page, report_uri: str) -> None:
    page.goto(report_uri)
    _open_all_disclosures(page)
    targets = {
        "button": "button[data-filter='all']",
        "summary": "details.tech summary",
        "link": "a",
    }
    for kind, selector in targets.items():
        element = page.locator(selector).first
        element.focus()
        assert element.evaluate("el => el.matches(':focus')"), f"{kind} is not focusable"
        outline = element.evaluate(_FOCUS_OUTLINE_JS)
        assert outline["style"] == "solid", (
            f"{kind} focus outline must be a solid ring, got style={outline['style']!r}"
        )
        width_px = float(outline["width"].removesuffix("px"))
        assert width_px >= 2.0, (
            f"{kind} focus outline must be >= 2px (DESIGN.md ring), got {outline['width']}"
        )


def test_reduced_motion_disables_transitions(page: Page, report_uri: str) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(report_uri)
    offenders = []
    for element in page.locator("button, a, summary").all():
        duration = element.evaluate("el => getComputedStyle(el).transitionDuration")
        if any(part.strip() != "0s" for part in duration.split(",")):
            offenders.append((element.evaluate("el => el.tagName"), duration))
    assert not offenders, f"transitions not disabled under reduced motion: {offenders}"


def test_print_status_contrast(page: Page, report_uri: str) -> None:
    page.emulate_media(media="print")
    page.goto(report_uri)
    badges = page.locator(".finding .status-marker")
    assert badges.count() == 6, f"expected 6 status badges, got {badges.count()}"
    failures = []
    for index in range(badges.count()):
        badge = badges.nth(index)
        colors = badge.evaluate(_PRINT_COLORS_JS)
        ratio = _contrast_ratio(tuple(colors["fg"]), tuple(colors["bg"]))
        if ratio < 4.5:
            failures.append((badge.get_attribute("class"), round(ratio, 2)))
    assert not failures, f"print status contrast below 4.5:1: {failures}"


# ---------------------------------------------------------------------------
# GROUP B — invariants that MUST PASS today (regression guards)
# ---------------------------------------------------------------------------


def test_offline_single_file_load_no_network(page: Page, report_uri: str) -> None:
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url))
    page.goto(report_uri)
    page.wait_for_load_state("load")
    external = [url for url in requests if url.startswith(("http://", "https://"))]
    assert external == [], f"unexpected external network requests: {external}"
    assert page.locator(".finding").count() == 6, "report did not render all findings"


def test_disclosures_native_keyboard_operable(page: Page, report_uri: str) -> None:
    page.goto(report_uri)
    details = page.locator("details.tech")
    assert details.count() > 0, "no native <details class='tech'> disclosures"
    first = details.first
    summary = first.locator("summary")
    assert summary.count() == 1, "disclosure missing a single <summary>"

    summary.focus()
    assert summary.evaluate("el => el.matches(':focus')"), "summary is not focusable"
    assert first.evaluate("el => el.open") is False

    page.keyboard.press("Enter")
    assert first.evaluate("el => el.open") is True, "Enter did not open the disclosure"
    page.keyboard.press("Space")
    assert first.evaluate("el => el.open") is False, "Space did not close the disclosure"


def test_four_sections_in_dom_order(page: Page, report_uri: str) -> None:
    page.goto(report_uri)
    headings = [heading.inner_text().strip() for heading in page.locator("h2").all()]
    for heading in SECTION_HEADINGS:
        assert heading in headings, f"missing section heading {heading!r}"
    positions = [headings.index(heading) for heading in SECTION_HEADINGS]
    assert positions == sorted(positions), f"section headings out of order: {headings}"

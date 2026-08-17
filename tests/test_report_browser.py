"""Persistent Chromium browser contracts for the Security License Lens HTML report.

The report is a single self-contained offline file opened via ``file://``, so these
tests render the real artifact through ``write_html_report`` and navigate with
``Path.as_uri()`` — never a dev server, never an external request.

Groups, deliberately partitioned:

* **ESTABLISHED INVARIANTS — must PASS today**: regression guards locking the
  current offline/disclosure/section/overflow behavior. This includes the former
  "RED redesign contracts" — the redesign has since landed, so those contracts
  are now green invariants and are reclassified here.
* **FIXTURE INTEGRITY**: one test guarantees the browser-safe fixture never
  renders a raw ``<script>`` payload and still covers every status/exposure/move
  variant.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page

from licenselens.models import Effort, ScanResult, Severity
from licenselens.report.bundle import build_report_bundle
from licenselens.report.html import write_html_report
from tests.report_fixtures import comprehensive_report

pytestmark = pytest.mark.browser

VIEWPORTS = [(375, 812), (768, 1024), (1024, 768), (1280, 900), (1440, 1000)]

SECTION_HEADINGS = [
    "Where you stand",
    "What you're paying for",
    "What matters most",
    "Findings",
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

# Constellation state under the current media emulation. Token colors are read
# through probe elements so `#F87171` custom-property values and computed
# `rgb(...)` colors share one serialization and can be compared directly;
# `digitsExpected` comes from server-rendered attributes, never a hardcoded figure.
_CONSTELLATION_STATE_JS = """() => {
    const probe = (prop) => {
        const el = document.createElement('span');
        el.style.color = 'var(' + prop + ')';
        document.body.appendChild(el);
        const color = getComputedStyle(el).color;
        el.remove();
        return color;
    };
    const node = document.querySelector('.constellation-point.status-gap');
    const countUp = document.querySelector('[data-count-up]');
    const figure = document.querySelector('.posture-figure[data-realized]');
    let digitsExpected = null;
    if (countUp) digitsExpected = countUp.getAttribute('data-count-up') + '% realized';
    else if (figure) digitsExpected = figure.getAttribute('data-realized');
    return {
        nodeColor: node ? getComputedStyle(node).color : null,
        actionColor: probe('--state-action'),
        neutralColor: probe('--state-neutral'),
        instant: document.body.classList.contains('instant'),
        revealed: document.body.classList.contains('revealed'),
        digitsText: (document.querySelector('.posture-digits') || {}).textContent || null,
        digitsExpected,
    };
}"""

# Owned SKUs table under a narrow viewport. The wrapper must become the overflow
# container (scrollWidth > clientWidth), the SKU name must occupy a single
# line box, and the page itself must never grow wider than the viewport.
_SKU_TABLE_STATE_JS = """() => {
    const wrapper = document.querySelector('.sku-strip .table-scroll');
    const nameSpan = wrapper.querySelector('tbody td .sku-name');
    const cell = nameSpan.parentElement;
    const cs = getComputedStyle(cell);
    return {
        scrollWidth: wrapper.scrollWidth,
        clientWidth: wrapper.clientWidth,
        nameRects: nameSpan.getClientRects().length,
        cellHeight: cell.clientHeight,
        cellLineHeight: parseFloat(cs.lineHeight),
        cellPadding: parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom),
        cellBorder: parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth),
        docScrollWidth: document.documentElement.scrollWidth,
        innerWidth: window.innerWidth,
    };
}"""

# License-count cells: hidden past the wrapper edge before scrolling, fully inside
# it after scrolling to the end (scrollLeft = scrollWidth).
_SKU_TABLE_END_JS = """() => {
    const wrapper = document.querySelector('.sku-strip .table-scroll');
    const cells = [...wrapper.querySelectorAll('td.num')];
    const wRect = wrapper.getBoundingClientRect();
    const before = cells.map(el => el.getBoundingClientRect().right - wRect.right);
    wrapper.scrollLeft = wrapper.scrollWidth;
    const after = cells.map(el => {
        const r = el.getBoundingClientRect();
        return { left: r.left - wRect.left, right: wRect.right - r.right };
    });
    return { beforeOverflow: Math.max(...before), after };
}"""

# Visible finding-list order. Both renderers expose their sortable rows inside
# [data-findings-list]: the single-file renders server-side .explore-row articles
# (data-check-id) that the sort control re-appends; the bundle renders client-side
# .finding-row articles (data-finding) re-rendered per refresh.
_FINDINGS_ORDER_JS = """() => {
    const list = document.querySelector('[data-findings-list]');
    if (!list) return [];
    return Array.from(list.querySelectorAll('.explore-row, .finding-row'))
        .filter((el) => !el.hidden)
        .map((el) => el.getAttribute('data-check-id') || el.getAttribute('data-finding'));
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


def _sort_probe_report() -> ScanResult:
    """Browser-safe fixture with three orthogonal perturbations so each sort
    key demonstrably reorders the findings list:

    * ``mde-onboard-gap`` becomes the only CRITICAL finding → severity sort
      moves it to the front (engine default starts with the gap finding);
    * ``pur-dlp-not-enforced`` becomes the only MINUTES effort → effort sort
      moves it to the front;
    * its title is renamed to "Audit DLP policy enforcement" so it sorts
      first alphabetically in the bundle's title comparator.
    """
    result = browser_safe_report()
    findings = []
    for finding in result.findings:
        if finding.check_id == "mde-onboard-gap":
            findings.append(finding.model_copy(update={"severity": Severity.CRITICAL}))
        elif finding.check_id == "pur-dlp-not-enforced":
            findings.append(
                finding.model_copy(
                    update={
                        "effort": Effort.MINUTES,
                        "title": "Audit DLP policy enforcement",
                        "customer_title": "Audit DLP policy enforcement",
                    }
                )
            )
        else:
            findings.append(finding)
    return result.model_copy(update={"findings": findings})


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

    # Scoped: bare `button[data-workload='endpoint']` also matches v2 constellation buttons.
    page.locator("[data-filter-bar] button[data-workload='endpoint']").focus()
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


def test_bundle_entry_offline_no_network(page: Page, tmp_path: Path) -> None:
    bundle = build_report_bundle(browser_safe_report(), tmp_path / "bundle")
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url))
    page.goto(bundle.entry_path.as_uri())
    page.wait_for_load_state("load")
    external = [url for url in requests if url.startswith(("http://", "https://"))]
    assert external == [], f"unexpected external network requests: {external}"
    assert page.locator(".finding-row").count() == 6, "bundle did not render all findings"
    stylesheets = page.evaluate("() => document.styleSheets.length")
    assert stylesheets >= 1, "external stylesheet was not applied"


# ---------------------------------------------------------------------------
# GROUP C — v2 design locks: constellation status colors under reduced motion
# and with JavaScript disabled, for BOTH renderers (single-file and bundle).
# ---------------------------------------------------------------------------

_RGB_TRIPLE = re.compile(r"rgb\((\d+),\s*(\d+),\s*(\d+)\)")


def _rgb_tuple(value: str) -> tuple[int, int, int]:
    if value.startswith("#") and len(value) == 7:
        return (int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16))
    match = _RGB_TRIPLE.fullmatch(value)
    if match:
        return tuple(int(group) for group in match.groups())
    raise ValueError(f"unexpected color serialization: {value!r}")


def _renderer_uri(renderer: str, tmp_path: Path, result: ScanResult | None = None) -> str:
    if result is None:
        result = browser_safe_report()
    if renderer == "single":
        return write_html_report(result, tmp_path / "report.html").as_uri()
    return build_report_bundle(result, tmp_path / "bundle").entry_path.as_uri()


def _cdp_computed_props(page: Page, selector: str) -> dict[str, str]:
    """Computed style via DevTools, which keeps working with page JavaScript off."""
    session = page.context.new_cdp_session(page)
    session.send("DOM.enable")
    session.send("CSS.enable")
    document = session.send("DOM.getDocument", {"depth": -1, "pierce": True})
    node = session.send(
        "DOM.querySelector", {"nodeId": document["root"]["nodeId"], "selector": selector}
    )
    assert node.get("nodeId"), f"{selector!r} not found in JS-disabled page"
    styles = session.send("CSS.getComputedStyleForNode", {"nodeId": node["nodeId"]})
    return {prop["name"]: prop["value"] for prop in styles["computedStyle"]}


def _cdp_legend_chip_colors(page: Page) -> list[str]:
    session = page.context.new_cdp_session(page)
    session.send("DOM.enable")
    session.send("CSS.enable")
    document = session.send("DOM.getDocument", {"depth": -1, "pierce": True})
    chips = session.send(
        "DOM.querySelectorAll",
        {"nodeId": document["root"]["nodeId"], "selector": ".constellation-legend-chip"},
    )
    colors: list[str] = []
    for node_id in chips["nodeIds"]:
        styles = session.send("CSS.getComputedStyleForNode", {"nodeId": node_id})
        color = next(
            (prop["value"] for prop in styles["computedStyle"] if prop["name"] == "color"),
            None,
        )
        if color:
            colors.append(color)
    return colors


def _assert_instant_resolve(state: dict[str, object]) -> None:
    assert state["instant"] is True, "body.instant was not added under reduced motion"
    assert state["revealed"] is False, "body.revealed must not be set under reduced motion"
    assert state["nodeColor"] == state["actionColor"], (
        f"status-gap node did not resolve to the action color: {state['nodeColor']!r}"
    )
    assert state["nodeColor"] != state["neutralColor"], (
        f"status-gap node stayed at the neutral token: {state['nodeColor']!r}"
    )
    assert state["digitsText"] == state["digitsExpected"], (
        "posture digits were not pinned to their server-rendered final value: "
        f"{state['digitsText']!r} != {state['digitsExpected']!r}"
    )


def test_single_file_reduced_motion_instant_resolve(page: Page, report_uri: str) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(report_uri)
    page.wait_for_load_state("load")
    _assert_instant_resolve(page.evaluate(_CONSTELLATION_STATE_JS))


def test_bundle_reduced_motion_instant_resolve(page: Page, tmp_path: Path) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(_renderer_uri("bundle", tmp_path))
    page.wait_for_load_state("load")
    _assert_instant_resolve(page.evaluate(_CONSTELLATION_STATE_JS))


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_js_disabled_constellation_status_colors(page: Page, tmp_path: Path, renderer: str) -> None:
    uri = _renderer_uri(renderer, tmp_path)
    context = page.context.browser.new_context(java_script_enabled=False)
    no_js = context.new_page()
    no_js.goto(uri)
    no_js.wait_for_load_state("load")

    node = _cdp_computed_props(no_js, ".constellation-point.status-gap")
    assert _rgb_tuple(node["color"]) == _rgb_tuple(node["--state-action"]), (
        f"{renderer}: status-gap node is not the action color without JS: {node['color']!r}"
    )
    assert _rgb_tuple(node["color"]) != _rgb_tuple(node["--state-neutral"]), (
        f"{renderer}: status-gap node fell back to the neutral token without JS"
    )

    chip_colors = _cdp_legend_chip_colors(no_js)
    distinct = {_rgb_tuple(color) for color in chip_colors}
    assert len(distinct) >= 2, (
        f"{renderer}: legend chips do not carry distinct status colors without JS: {chip_colors}"
    )
    context.close()


# ---------------------------------------------------------------------------
# GROUP D — v2 mobile table lock: the Owned SKUs table scrolls inside its
# .table-scroll wrapper at a 375px viewport instead of clipping at the page
# edge; SKU names stay on one line and the license-count column is
# reachable by scrolling, never by growing the page.
# ---------------------------------------------------------------------------


def test_owned_skus_table_scrolls_inside_wrapper(page: Page, report_uri: str) -> None:
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(report_uri)
    page.wait_for_load_state("load")
    _open_all_disclosures(page)

    state = page.evaluate(_SKU_TABLE_STATE_JS)
    assert state["scrollWidth"] > state["clientWidth"], (
        "SKU table does not scroll inside its wrapper: "
        f"scrollWidth={state['scrollWidth']} <= clientWidth={state['clientWidth']}"
    )
    assert state["nameRects"] == 1, (
        f"SKU name wrapped in the scrollable table: {state['nameRects']} line boxes"
    )
    single_line = state["cellLineHeight"] + state["cellPadding"] + state["cellBorder"]
    assert state["cellHeight"] <= single_line + 1, (
        "part number cell is taller than a single line: "
        f"{state['cellHeight']}px > {single_line}px (line + padding + border)"
    )
    assert state["docScrollWidth"] <= state["innerWidth"], (
        "SKU table pushed the page wider than the viewport: "
        f"scrollWidth={state['docScrollWidth']} > innerWidth={state['innerWidth']}"
    )

    end = page.evaluate(_SKU_TABLE_END_JS)
    assert end["beforeOverflow"] > 0, (
        "license-count cells were already visible before scrolling — table never overflowed"
    )
    for cell in end["after"]:
        assert cell["left"] >= -1 and cell["right"] >= -1, (
            f"license-count cell not fully visible after scrollLeft=scrollWidth: {cell}"
        )


# ---------------------------------------------------------------------------
# GROUP E — v2 constellation field/legend restructure locks (todo 5). The
# status legend renders as a sibling block BELOW the field (never a grid
# column), the field scrolls inside itself at 375px, the last group's caption
# never clips at 1280px, and the first group column is `identity` at every
# width — for BOTH renderers (single-file and bundle).
# ---------------------------------------------------------------------------

# Constellation field/legend layout under the current viewport. Chips report
# their computed status colors keyed by variant (the shared two-class cascade).
_CONSTELLATION_LAYOUT_JS = """() => {
    const field = document.querySelector('.constellation');
    const legend = document.querySelector('.constellation-legend');
    const groups = Array.from(document.querySelectorAll('.constellation-group'));
    const last = groups[groups.length - 1] || null;
    const caption = last ? last.querySelector('.constellation-caption') : null;
    const label = last ? last.querySelector('.constellation-caption-label') : null;
    const fieldRect = field.getBoundingClientRect();
    const legendRect = legend.getBoundingClientRect();
    const lastRect = last ? last.getBoundingClientRect() : null;
    const captionRect = caption ? caption.getBoundingClientRect() : null;
    const chips = {};
    document.querySelectorAll('.constellation-legend-chip').forEach((el) => {
        const match = /(?:^|\\s)status-([a-z_]+)/.exec(el.className);
        if (match) chips[match[1]] = getComputedStyle(el).color;
    });
    return {
        groupCount: groups.length,
        groupLefts: groups.map((el) => el.getBoundingClientRect().left),
        firstWorkload: groups.length ? groups[0].getAttribute('data-workload') : null,
        legendTop: legendRect.top,
        fieldBottom: fieldRect.bottom,
        fieldRight: fieldRect.right,
        legendRight: legendRect.right,
        fieldScrollWidth: field.scrollWidth,
        fieldClientWidth: field.clientWidth,
        lastCaptionText: label ? label.textContent.trim() : null,
        lastCaptionOverflow: caption ? caption.scrollWidth - caption.clientWidth : null,
        lastCaptionLeft: captionRect ? captionRect.left : null,
        lastCaptionRight: captionRect ? captionRect.right : null,
        lastGroupLeft: lastRect ? lastRect.left : null,
        lastGroupRight: lastRect ? lastRect.right : null,
        chipColors: chips,
        docScrollWidth: document.documentElement.scrollWidth,
        innerWidth: window.innerWidth,
    };
}"""


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_constellation_legend_sits_below_scrolling_field(
    page: Page, tmp_path: Path, renderer: str
) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")

    state = page.evaluate(_CONSTELLATION_LAYOUT_JS)
    assert state["groupCount"] >= 3, f"{renderer}: fixture constellation unexpectedly small"
    assert state["legendTop"] >= state["fieldBottom"], (
        f"{renderer}: legend is not below the field: legend top {state['legendTop']}px "
        f"< field bottom {state['fieldBottom']}px"
    )
    assert state["legendRight"] <= state["innerWidth"] + 1, (
        f"{renderer}: legend clips past the viewport: right {state['legendRight']}px "
        f"> innerWidth {state['innerWidth']}px"
    )
    assert state["docScrollWidth"] <= state["innerWidth"], (
        f"{renderer}: constellation pushed the page wider than the viewport: "
        f"{state['docScrollWidth']}px > {state['innerWidth']}px"
    )
    assert state["fieldScrollWidth"] > state["fieldClientWidth"], (
        f"{renderer}: the field does not scroll inside itself at 375px: "
        f"scrollWidth={state['fieldScrollWidth']}px <= clientWidth={state['fieldClientWidth']}px"
    )


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_constellation_legend_chip_colors_distinct_per_status(
    page: Page, tmp_path: Path, renderer: str
) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")

    state = page.evaluate(_CONSTELLATION_LAYOUT_JS)
    chips = state["chipColors"]
    for variant in ("gap", "partial", "ok", "not_licensed", "skipped", "error"):
        assert chips.get(variant), f"{renderer}: missing legend chip for status {variant!r}"
    representative = {chips[variant] for variant in ("gap", "partial", "ok", "not_licensed")}
    assert len(representative) == 4, (
        f"{renderer}: legend chip colors do not differ per status: {chips}"
    )


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_constellation_last_caption_never_clips_at_1280(
    page: Page, tmp_path: Path, renderer: str
) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")

    state = page.evaluate(_CONSTELLATION_LAYOUT_JS)
    assert state["lastCaptionText"], f"{renderer}: last group caption label is empty"
    assert state["lastCaptionOverflow"] <= 0, (
        f"{renderer}: last group caption overflows its own box at 1280px: "
        f"scrollWidth exceeds clientWidth by {state['lastCaptionOverflow']}px"
    )
    assert state["lastCaptionLeft"] >= state["lastGroupLeft"] - 1, (
        f"{renderer}: last group caption starts left of its column at 1280px"
    )
    assert state["lastCaptionRight"] <= state["lastGroupRight"] + 1, (
        f"{renderer}: last group caption clips past its column at 1280px: "
        f"{state['lastCaptionRight']}px > {state['lastGroupRight']}px"
    )
    assert state["lastCaptionRight"] <= state["fieldRight"] + 1, (
        f"{renderer}: last group caption clips past the field at 1280px: "
        f"{state['lastCaptionRight']}px > {state['fieldRight']}px"
    )


@pytest.mark.parametrize("renderer", ["single", "bundle"])
@pytest.mark.parametrize("width", [375, 1280])
def test_constellation_first_group_is_identity_at_every_width(
    page: Page, tmp_path: Path, renderer: str, width: int
) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")

    state = page.evaluate(_CONSTELLATION_LAYOUT_JS)
    assert state["firstWorkload"] == "identity", (
        f"{renderer}@{width}px: first constellation group is {state['firstWorkload']!r}, "
        "expected 'identity'"
    )
    assert state["groupLefts"][0] <= min(state["groupLefts"]) + 0.5, (
        f"{renderer}@{width}px: the identity group is not the leftmost column"
    )


# ---------------------------------------------------------------------------
# GROUP F — brief §25 sort-control lock (todo 10). The findings-list sort
# select (#finding-sort) exists in BOTH renderers (single-file report.html.j2
# carries data-sort-select on the same element; bundle entry.html.j2 is
# identical minus the data attribute), so this lock covers both. Each sort
# key must produce its documented deterministic order — locked in full, with
# the first row additionally locked per key where the probe perturbs it.
# ---------------------------------------------------------------------------

# Engine/default order of the probe's findings list (canonical view-model order).
_SORT_ENGINE_ORDER = [
    "id-ca-priv-gaps",
    "mde-onboard-gap",
    "id-security-defaults-on",
    "sen-ueba-not-enabled",
    "mdo-p2-policies-default",
    "pur-dlp-not-enforced",
]

# Per-renderer expected orders for the probe report.
#   * severity: CRITICAL probe first; HIGH ties break by STATUS_ORDER then
#     check_id in the bundle (app.js compareSeverity), which for this probe
#     (distinct statuses) equals the single-file's frozen _idx fallback — the
#     two renderers agree.
#   * effort: MINUTES probe first; HOURS ties break by severity then check_id
#     in the bundle (compareEffort — so the CRITICAL probe ranks next), but
#     keep engine order in the single-file (frozen _idx fallback) — the tails
#     differ.
#   * title: the bundle compares finding titles only; the single-file's frozen
#     JS compares the whole row textContent, which is dominated by the status
#     presentation word ("Action required" < "Incomplete" < "Not assessed" <
#     "Not licensed" < "Operational" < "Verification failed") — hence the gap
#     finding stays first in the single-file title sort by design.
_SORT_EXPECTED = {
    "single": {
        "severity": [
            "mde-onboard-gap",
            "id-ca-priv-gaps",
            "id-security-defaults-on",
            "sen-ueba-not-enabled",
            "mdo-p2-policies-default",
            "pur-dlp-not-enforced",
        ],
        "effort": [
            "pur-dlp-not-enforced",
            "id-ca-priv-gaps",
            "mde-onboard-gap",
            "id-security-defaults-on",
            "sen-ueba-not-enabled",
            "mdo-p2-policies-default",
        ],
        "title": [
            "id-ca-priv-gaps",
            "mde-onboard-gap",
            "mdo-p2-policies-default",
            "sen-ueba-not-enabled",
            "id-security-defaults-on",
            "pur-dlp-not-enforced",
        ],
    },
    "bundle": {
        "severity": [
            "mde-onboard-gap",
            "id-ca-priv-gaps",
            "id-security-defaults-on",
            "sen-ueba-not-enabled",
            "mdo-p2-policies-default",
            "pur-dlp-not-enforced",
        ],
        "effort": [
            "pur-dlp-not-enforced",
            "mde-onboard-gap",
            "id-ca-priv-gaps",
            "id-security-defaults-on",
            "mdo-p2-policies-default",
            "sen-ueba-not-enabled",
        ],
        "title": [
            "pur-dlp-not-enforced",
            "id-ca-priv-gaps",
            "mde-onboard-gap",
            "mdo-p2-policies-default",
            "id-security-defaults-on",
            "sen-ueba-not-enabled",
        ],
    },
}

# Keys whose sort demonstrably changes the FIRST row on this renderer. The
# single-file title sort legitimately keeps the gap finding first (status word
# dominates its frozen textContent comparator), so title is bundle-only here.
_SORT_FIRST_ROW_CHANGES = {
    "single": ("severity", "effort"),
    "bundle": ("severity", "effort", "title"),
}


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_findings_sort_control_reorders_deterministically(
    page: Page, tmp_path: Path, renderer: str
) -> None:
    probe = _sort_probe_report()
    page.emulate_media(reduced_motion="reduce")
    page.goto(_renderer_uri(renderer, tmp_path, result=probe))
    page.wait_for_load_state("load")

    engine_order = [finding.check_id for finding in probe.findings]
    assert engine_order == _SORT_ENGINE_ORDER, "sort probe findings drifted from the engine order"
    # The DEFAULT is severity (criticality) order, most critical first.
    assert page.evaluate(_FINDINGS_ORDER_JS) == _SORT_EXPECTED[renderer]["severity"], (
        f"{renderer}: default (severity) order diverged from the criticality order"
    )
    assert page.locator("#finding-sort").input_value() == "severity", (
        f"{renderer}: sort control does not default to severity"
    )

    expected = _SORT_EXPECTED[renderer]
    for key in ("severity", "effort", "title"):
        page.select_option("#finding-sort", key)
        first_run = page.evaluate(_FINDINGS_ORDER_JS)
        assert first_run == expected[key], (
            f"{renderer}: {key} sort order {first_run} != expected {expected[key]}"
        )
        if key in _SORT_FIRST_ROW_CHANGES[renderer]:
            assert first_run[0] != engine_order[0], (
                f"{renderer}: {key} sort did not change the first finding row "
                f"(still {first_run[0]!r})"
            )

        page.reload()
        page.wait_for_load_state("load")
        page.select_option("#finding-sort", key)
        second_run = page.evaluate(_FINDINGS_ORDER_JS)
        assert second_run == first_run, (
            f"{renderer}: {key} sort is not deterministic across reloads: "
            f"{first_run} != {second_run}"
        )


# ---------------------------------------------------------------------------
# GROUP G — a11y + print regression gates (todo 26). Heading hierarchy
# (no skipped levels), keyboard reachability + visible focus + accessible
# names for the primary controls (search, sort, filters, constellation
# captions), textual equivalents for every visualization, and print-media
# emulation (content present, disclosures expanded, chart fallbacks visible,
# no blank sections). Both renderers.
#
# Both renderers own the DESIGN focus ring (solid >= 2px accent outline): the
# single-file foundation carries one and the bundle's app.css carries its own
# copy, so the gate holds every renderer to the identical ring standard.
# ---------------------------------------------------------------------------

# Heading levels in DOM order. Levels only — wording is locked elsewhere.
_HEADING_LEVELS_JS = """() => Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6'))
    .map((el) => +el.tagName[1])"""

# Every keyboard-focusable element in tab order, restricted to elements with
# a layout box (display/visibility/rect mirror the browser's own tab filter).
_FOCUSABLE_JS = """() => Array.from(document.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), ' +
      'select:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'))
    .filter((el) => {
        const style = getComputedStyle(el);
        const rect = el.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden'
            && rect.width > 0 && rect.height > 0;
    })
    .map((el) => ({
        tag: el.tagName.toLowerCase(),
        id: el.id,
        cls: el.getAttribute('class') || '',
    }))"""

# Focused-element state read after each Tab press: identity, computed focus
# ring, accessible name (aria-label -> label[for] -> aria-labelledby ->
# text content), and the aria-pressed tri-state for toggle controls.
_FOCUSED_STOP_JS = """() => {
    const el = document.activeElement;
    if (!el || el === document.body) return null;
    const style = getComputedStyle(el);
    let name = el.getAttribute('aria-label');
    if (!name && el.id) {
        const label = document.querySelector('label[for="' + el.id + '"]');
        if (label) name = label.textContent.trim();
    }
    if (!name && el.getAttribute('aria-labelledby')) {
        const ref = document.getElementById(el.getAttribute('aria-labelledby'));
        if (ref) name = ref.textContent.trim();
    }
    if (!name) name = (el.textContent || '').trim();
    return {
        tag: el.tagName.toLowerCase(),
        id: el.id,
        cls: el.getAttribute('class') || '',
        outlineStyle: style.outlineStyle,
        outlineWidth: parseFloat(style.outlineWidth) || 0,
        pressed: el.getAttribute('aria-pressed'),
        name: name.slice(0, 80),
    };
}"""

_PRIMARY_CONTROLS = ("search", "sort", "filter", "caption")

# Textual equivalents of the visualizations: every role="img" visual's
# accessible name/description resolution, every chart data table's caption
# and row count, the constellation nodes' aria-labels, and the field/legend
# group labels.
_CHART_EQUIVALENTS_JS = """() => {
    const resolve = (id) => {
        const ref = id ? document.getElementById(id) : null;
        return ref ? ref.textContent.trim() : null;
    };
    const visuals = Array.from(document.querySelectorAll('[role="img"]')).map((el) => ({
        name: resolve(el.getAttribute('aria-labelledby')) || el.getAttribute('aria-label') || '',
        desc: resolve(el.getAttribute('aria-describedby')) || '',
    }));
    const tables = Array.from(
        document.querySelectorAll('.chart-table, [data-chart-table]')
    ).map((table) => {
        const caption = table.querySelector('caption');
        return {
            caption: caption ? caption.textContent.trim() : '',
            rows: table.querySelectorAll('tbody tr').length,
        };
    });
    const nodes = Array.from(document.querySelectorAll('.constellation-point'))
        .map((el) => (el.getAttribute('aria-label') || '').trim());
    const field = document.querySelector('.constellation');
    const legend = document.querySelector('.constellation-legend');
    return {
        visuals,
        tables,
        nodes,
        fieldLabel: field ? field.getAttribute('aria-label') || '' : null,
        legendLabel: legend ? legend.getAttribute('aria-label') || '' : null,
        srDescs: {
            radial: resolve('radial-desc'),
            dist: resolve('dist-desc'),
            status: resolve('chart-status-desc'),
            workload: resolve('chart-workload-desc'),
            severity: resolve('chart-severity-desc'),
            gauge: resolve('posture-gauge-desc'),
        },
    };
}"""

# Print-media state: per-section visibility (a blank section is a print
# regression), chart-table fallback visibility, radial replacement, finding
# visibility, disclosure expansion, and hidden print chrome.
_PRINT_STATE_JS = """() => {
    const style = (selector) => {
        const el = document.querySelector(selector);
        return el ? getComputedStyle(el) : null;
    };
    const sections = Array.from(document.querySelectorAll('main section')).map((s) => {
        const computed = getComputedStyle(s);
        const rect = s.getBoundingClientRect();
        return {
            id: s.id,
            display: computed.display,
            opacity: computed.opacity,
            height: Math.round(rect.height),
            text: (s.innerText || '').trim().length,
        };
    });
    return {
        sections,
        chartTables: Array.from(
            document.querySelectorAll('.chart-table, [data-chart-table]')
        ).map((t) => ({
            position: getComputedStyle(t).position,
            display: getComputedStyle(t).display,
        })),
        radialSvg: style('.radial-svg') ? style('.radial-svg').display : null,
        radialLine: style('.radial-print-line') ? style('.radial-print-line').position : null,
        gaugeViz: style('.posture-gauge__viz') ? style('.posture-gauge__viz').display : null,
        gaugePrint: style('.posture-gauge__print') ? style('.posture-gauge__print').display : null,
        findingDisplays: Array.from(
            document.querySelectorAll('.finding, .explore-row, .print-finding')
        ).map((el) => getComputedStyle(el).display),
        closedDetailsBodies: Array.from(
            document.querySelectorAll('details.tech:not([open]) .tech-body')
        ).map((el) => getComputedStyle(el).display),
        printListDisplay: style('[data-print-list]') ? style('[data-print-list]').display : null,
        searchBox: style('.search-box') ? style('.search-box').display : null,
    };
}"""


def _primary_kind(stop: dict[str, str] | None) -> str | None:
    if stop is None:
        return None
    if stop["id"] == "finding-search":
        return "search"
    if stop["id"] == "finding-sort":
        return "sort"
    if "filter-button" in stop["cls"] or "filter-chip" in stop["cls"]:
        return "filter"
    if "constellation-caption" in stop["cls"]:
        return "caption"
    return None


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_heading_hierarchy_never_skips_a_level(page: Page, tmp_path: Path, renderer: str) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")

    levels = page.evaluate(_HEADING_LEVELS_JS)
    assert levels, f"{renderer}: no headings found in the rendered report"
    assert levels.count(1) == 1, f"{renderer}: expected exactly one h1, got {levels.count(1)}"
    assert levels[0] == 1, f"{renderer}: the document must open with the h1"
    for previous, current in zip(levels, levels[1:], strict=False):
        assert current <= previous + 1, (
            f"{renderer}: heading hierarchy skips from h{previous} to h{current}"
        )


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_primary_controls_tab_reachable_with_focus_and_names(
    page: Page, tmp_path: Path, renderer: str
) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")
    page.evaluate("() => document.activeElement && document.activeElement.blur()")

    focusable = page.evaluate(_FOCUSABLE_JS)
    seen: dict[str, dict[str, object]] = {}
    # Real Tab navigation from an unfocused document: every primary control
    # must appear in the actual keyboard sequence, not merely be focusable.
    for _ in range(len(focusable) + 1):
        page.keyboard.press("Tab")
        stop = page.evaluate(_FOCUSED_STOP_JS)
        kind = _primary_kind(stop)
        if kind is not None and kind not in seen:
            seen[kind] = stop
    missing = [kind for kind in _PRIMARY_CONTROLS if kind not in seen]
    assert not missing, f"{renderer}: primary controls not reached via Tab navigation: {missing}"

    for kind in _PRIMARY_CONTROLS:
        stop = seen[kind]
        assert stop["name"], f"{renderer}: {kind} control has no accessible name"
        assert stop["outlineStyle"] == "solid" and stop["outlineWidth"] >= 2, (
            f"{renderer}: {kind} control lost the DESIGN focus ring (solid >= 2px): "
            f"outline={stop['outlineStyle']!r} width={stop['outlineWidth']}"
        )
        if kind in ("filter", "caption"):
            assert stop["pressed"] in ("true", "false"), (
                f"{renderer}: {kind} control missing aria-pressed='true'|'false'"
            )

    assert seen["search"]["name"] == "Search findings", (
        f"{renderer}: search input accessible name is {seen['search']['name']!r}"
    )
    assert seen["sort"]["name"] == "Sort findings", (
        f"{renderer}: sort select accessible name is {seen['sort']['name']!r}"
    )


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_primary_controls_respond_to_keyboard_activation(
    page: Page, tmp_path: Path, renderer: str
) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")

    def visible_count() -> str:
        return page.locator("[data-visible-count]").inner_text().strip()

    page.locator("#finding-search").focus()
    page.keyboard.type("UEBA")
    assert visible_count() == "1", (
        f"{renderer}: typing a search term did not narrow to 1 finding (got {visible_count()})"
    )
    # The searchable text now includes the collapsed row's belief-block content
    # ("Search titles, checks, evidence"), so a term that appears in one
    # finding's title and another finding's Expected slot matches both.
    page.locator("#finding-search").fill("Conditional")
    assert visible_count() == "2", (
        f"{renderer}: search did not reach the belief-block evidence text (got {visible_count()})"
    )
    page.locator("#finding-search").fill("")
    assert visible_count() == "6", (
        f"{renderer}: clearing the search did not restore all findings (got {visible_count()})"
    )

    page.locator("#finding-sort").focus()
    page.keyboard.type("s")
    assert page.locator("#finding-sort").input_value() == "severity", (
        f"{renderer}: keyboard typeahead did not move the sort select to the severity key"
    )

    filter_selector = (
        "button[data-filter='gap']" if renderer == "single" else "button[data-filter-value='gap']"
    )
    toggle = page.locator(filter_selector).first
    toggle.focus()
    page.keyboard.press("Enter")
    assert toggle.get_attribute("aria-pressed") == "true", (
        f"{renderer}: Enter did not press the status filter button"
    )
    assert visible_count() == "1", (
        f"{renderer}: pressed status filter did not narrow to 1 finding (got {visible_count()})"
    )
    page.keyboard.press("Enter")
    assert toggle.get_attribute("aria-pressed") == "false", (
        f"{renderer}: second Enter did not unpress the status filter button"
    )
    assert visible_count() == "6", (
        f"{renderer}: unpressed status filter did not restore all findings (got {visible_count()})"
    )

    caption = page.locator(".constellation-caption").first
    caption.focus()
    page.keyboard.press("Enter")
    assert caption.get_attribute("aria-pressed") == "true", (
        f"{renderer}: Enter did not activate the constellation caption"
    )
    # Activating the caption reorders the constellation columns in place, which
    # detaches the focused button; restore focus before toggling back.
    caption.focus()
    page.keyboard.press("Enter")
    assert caption.get_attribute("aria-pressed") == "false", (
        f"{renderer}: second Enter did not deactivate the constellation caption"
    )


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_visualizations_have_textual_equivalents(page: Page, tmp_path: Path, renderer: str) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")

    state = page.evaluate(_CHART_EQUIVALENTS_JS)
    assert len(state["visuals"]) >= 4, (
        f"{renderer}: expected at least 4 role=img visualizations, got {len(state['visuals'])}"
    )
    for index, visual in enumerate(state["visuals"]):
        assert visual["name"], f"{renderer}: visualization {index} has no accessible name"
        assert visual["desc"], f"{renderer}: visualization {index} has no accessible description"

    expected_tables = 5 if renderer == "single" else 4
    assert len(state["tables"]) == expected_tables, (
        f"{renderer}: expected {expected_tables} chart data tables, got {len(state['tables'])}"
    )
    for table in state["tables"]:
        assert table["caption"], f"{renderer}: chart data table missing a caption"
        assert table["rows"] >= 1, f"{renderer}: chart data table has no data rows"

    assert state["fieldLabel"], f"{renderer}: constellation field group has no aria-label"
    assert state["legendLabel"], f"{renderer}: constellation legend has no aria-label"
    assert state["nodes"], f"{renderer}: no constellation nodes rendered"
    for node_label in state["nodes"]:
        assert node_label, f"{renderer}: constellation node missing its aria-label"

    # Renderer-specific sr-only descriptions referenced by the visuals.
    if renderer == "single":
        for key in ("radial", "dist", "status", "workload", "severity"):
            assert state["srDescs"][key], f"{renderer}: missing sr-only description {key!r}"
    else:
        assert state["srDescs"]["gauge"], f"{renderer}: posture gauge sr-only description missing"


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_print_emulation_renders_complete_expanded_artifact(
    page: Page, tmp_path: Path, renderer: str
) -> None:
    # Reduced motion keeps the opening choreography at its instant final state,
    # so the print assertions never race an animation.
    page.emulate_media(media="print", reduced_motion="reduce")
    page.goto(_renderer_uri(renderer, tmp_path))
    page.wait_for_load_state("load")

    state = page.evaluate(_PRINT_STATE_JS)

    # No blank sections: every section is displayed, fully opaque, laid out,
    # and carries real content.
    for section in state["sections"]:
        assert section["display"] != "none", (
            f"{renderer}: section {section['id']!r} is display:none in print"
        )
        assert section["opacity"] == "1", (
            f"{renderer}: section {section['id']!r} is not fully opaque in print"
        )
        assert section["height"] >= 40, (
            f"{renderer}: section {section['id']!r} has no layout height in print"
        )
        assert section["text"] >= 20, (
            f"{renderer}: section {section['id']!r} is blank in print ({section['text']} chars)"
        )

    # Every finding (collapsed rows + belief articles, or the print list)
    # stays in the printed artifact. The single-file carries 6 belief
    # articles inside 6 collapsed rows; the bundle hides its interactive
    # list in print and shows 6 dedicated print findings instead.
    expected_findings = 12 if renderer == "single" else 6
    assert len(state["findingDisplays"]) == expected_findings, (
        f"{renderer}: expected {expected_findings} finding displays in print, "
        f"got {len(state['findingDisplays'])}"
    )
    assert all(display != "none" for display in state["findingDisplays"]), (
        f"{renderer}: a finding is hidden in the printed artifact"
    )

    # Chart data tables become the visible print fallback (position static,
    # never clipped or display:none).
    assert state["chartTables"], f"{renderer}: no chart data tables rendered"
    for table in state["chartTables"]:
        assert table["position"] == "static" and table["display"] != "none", (
            f"{renderer}: chart data table is not a visible print fallback: {table}"
        )

    # Radial gauge is replaced by its textual line; screen chrome is removed.
    if renderer == "single":
        assert state["radialSvg"] == "none", f"{renderer}: radial svg prints"
        assert state["radialLine"] == "static", (
            f"{renderer}: radial print line is not the visible fallback"
        )
    else:
        assert state["gaugeViz"] == "none", f"{renderer}: posture gauge svg prints"
        assert state["gaugePrint"] == "block", (
            f"{renderer}: posture gauge print line is not visible"
        )
        assert state["printListDisplay"] == "block", (
            f"{renderer}: the dedicated print list is not displayed"
        )

    # Every renderer's print stylesheet expands every closed disclosure:
    # technical evidence is part of the printed record.
    assert state["closedDetailsBodies"], (
        f"{renderer}: no closed disclosures found to expand in print"
    )
    assert all(display == "block" for display in state["closedDetailsBodies"]), (
        f"{renderer}: a closed disclosure's content is hidden in print"
    )

    assert state["searchBox"] == "none", (
        f"{renderer}: the search control is not removed from the printed artifact"
    )


# ---------------------------------------------------------------------------
# GROUP H — below-fold section reveal lock (threshold-0.12 regression). The
# sections B–E are revealed by a one-shot IntersectionObserver. With the old
# ``threshold: 0.12``, a section taller than ~8.3× the viewport can never
# intersect 12% of its own area, so the observer never fires and the section
# stays at opacity 0 — a long blank stretch. The fix observes ``threshold: 0``
# so ANY visible pixel reveals the section, regardless of its height. This test
# runs with real motion (no reduced-motion emulation, which would bypass the
# observer entirely) and scrolls incrementally — a single ``scrollTo(bottom)``
# jump would skip the middle sections and mask the bug.
# ---------------------------------------------------------------------------

# Reveal targets per renderer: the single-file template marks sections B/D/E
# with ``.reveal-target``; the bundle marks B/C/D/E with ``[data-reveal]``.
# Both add ``.is-revealed`` when the observer fires.
_REVEAL_SELECTORS = {
    "single": "main > section.reveal-target",
    "bundle": "[data-reveal]",
}

# Per-reveal-target geometry: content height relative to the viewport height.
_REVEAL_HEIGHTS_JS = """selector => Array.from(document.querySelectorAll(selector))
    .map((el) => ({ id: el.id || "", ratio: el.scrollHeight / window.innerHeight }))"""

# Post-scroll reveal state: class marker and computed opacity per target.
_REVEAL_STATE_JS = """selector => Array.from(document.querySelectorAll(selector))
    .map((el) => ({
        id: el.id || "",
        revealed: el.classList.contains('is-revealed'),
        opacity: getComputedStyle(el).opacity,
    }))"""

# Incremental scroll: step through the document so every below-fold section's
# leading edge actually crosses the viewport (a single bottom jump never lets
# the observer see the middle sections), then hold at the bottom long enough
# for the 250ms reveal transition + its per-section stagger (≤160ms) to finish
# so computed opacity is stable at 1.
_SCROLL_INCREMENTALLY_JS = """() => (async () => {
    const step = Math.floor(window.innerHeight * 0.8);
    const total = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
    for (let y = 0; y < total; y += step) {
        window.scrollTo(0, y);
        await new Promise((r) => setTimeout(r, 40));
    }
    window.scrollTo(0, total);
    await new Promise((r) => setTimeout(r, 700));
})()"""


def _tall_report() -> ScanResult:
    """Browser-safe fixture with ~300 cloned gap findings plus a 40x-cloned
    capability list so the merged Findings section (single-file) and section
    B (bundle — its findings list paginates at 25 rows) each dwarf any
    viewport — tall enough that 12% of the section could never fit on screen
    at once."""
    result = browser_safe_report()
    base = next(finding for finding in result.findings if finding.check_id == "id-ca-priv-gaps")
    clones = [
        base.model_copy(update={"check_id": f"{base.check_id}-dup-{index}"}) for index in range(300)
    ]
    capability_clones = [
        summary.model_copy(update={"id": f"{summary.id}-dup-{index}"})
        for index in range(40)
        for summary in result.capability_summaries
    ]
    return result.model_copy(
        update={
            "findings": [*result.findings, *clones],
            "capability_summaries": [*result.capability_summaries, *capability_clones],
        }
    )


@pytest.mark.parametrize("renderer", ["single", "bundle"])
def test_below_fold_sections_reveal_on_scroll(page: Page, tmp_path: Path, renderer: str) -> None:
    """Every below-fold section reveals after an incremental scroll, however tall.

    Guards the ``threshold: 0.12`` reveal bug: with a 12% visibility threshold,
    a section taller than ~8.3× the viewport never intersects enough of itself
    to trigger the one-shot IntersectionObserver, so it remains at opacity 0
    and renders as a long blank area. The observer must fire on any visible
    pixel (``threshold: 0``) so arbitrarily tall sections reveal as soon as
    their leading edge is scrolled into view.
    """
    page.set_viewport_size({"width": 800, "height": 700})
    page.goto(_renderer_uri(renderer, tmp_path, result=_tall_report()))
    page.wait_for_load_state("load")

    selector = _REVEAL_SELECTORS[renderer]
    heights = page.evaluate(_REVEAL_HEIGHTS_JS, selector)
    assert len(heights) >= 3, f"{renderer}: expected B/D/E (or more) reveal targets"
    max_ratio = max(entry["ratio"] for entry in heights)
    assert max_ratio > 9.0, (
        f"{renderer}: tallest reveal target is only {max_ratio:.1f}x the viewport; "
        "the tall fixture must exceed the ~8.3x threshold-0.12 danger zone or the "
        "test no longer exercises the bug"
    )

    page.evaluate(_SCROLL_INCREMENTALLY_JS)

    state = page.evaluate(_REVEAL_STATE_JS, selector)
    unrevealed = [entry for entry in state if not entry["revealed"] or entry["opacity"] != "1"]
    assert not unrevealed, (
        f"{renderer}: sections left unrevealed after incremental scroll: {unrevealed}"
    )

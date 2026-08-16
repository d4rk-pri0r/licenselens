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

from licenselens.models import ScanResult
from licenselens.report.bundle import build_report_bundle
from licenselens.report.html import write_html_report
from tests.report_fixtures import comprehensive_report

pytestmark = pytest.mark.browser

VIEWPORTS = [(375, 812), (768, 1024), (1024, 768), (1280, 900), (1440, 1000)]

SECTION_HEADINGS = [
    "Where you stand",
    "What you're paying for",
    "What matters most",
    "Why LicenseLens believes this",
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
# through probe elements so `#E5695F` custom-property values and computed
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
# container (scrollWidth > clientWidth), the mono part number must occupy a single
# line box, and the page itself must never grow wider than the viewport.
_SKU_TABLE_STATE_JS = """() => {
    const wrapper = document.querySelector('.sku-strip .table-scroll');
    const code = wrapper.querySelector('tbody td code');
    const cell = code.parentElement;
    const cs = getComputedStyle(cell);
    return {
        scrollWidth: wrapper.scrollWidth,
        clientWidth: wrapper.clientWidth,
        codeRects: code.getClientRects().length,
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
    assert page.locator(".finding").count() == 6, "bundle did not render all findings"
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


def _renderer_uri(renderer: str, tmp_path: Path) -> str:
    if renderer == "single":
        return write_html_report(browser_safe_report(), tmp_path / "report.html").as_uri()
    return build_report_bundle(browser_safe_report(), tmp_path / "bundle").entry_path.as_uri()


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
def test_js_disabled_constellation_status_colors(
    page: Page, tmp_path: Path, renderer: str
) -> None:
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
        f"{renderer}: legend chips do not carry distinct status colors without JS: "
        f"{chip_colors}"
    )
    context.close()


# ---------------------------------------------------------------------------
# GROUP D — v2 mobile table lock: the Owned SKUs table scrolls inside its
# .table-scroll wrapper at a 375px viewport instead of clipping at the page
# edge; mono part numbers stay on one line and the license-count column is
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
    assert state["codeRects"] == 1, (
        f"part number wrapped in the scrollable table: {state['codeRects']} line boxes"
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

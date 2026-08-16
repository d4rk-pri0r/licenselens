"""Structural render contracts for the Security License Lens HTML report.

Two groups, deliberately partitioned:

* **ESTABLISHED INVARIANTS — must PASS today**: offline/autoescape/DOM/filter/
  JSON/heading contracts that must remain green across visual redesigns.
* **WARM-CHARCOAL (v2) DESIGN-SIGNATURE CONTRACTS**: warm charcoal canvas
  (#191714), champagne-ivory accent tokens, no violet/brass/navy signatures,
  every declared surface token consumed by a selector, and the §4 radius
  stops (0/2/6/10/16/999px — 999px pill authorized ONLY for proportion-based
  fills and constellation node circles).
* **FIXTURE INTEGRITY**: preamble asserting fixtures stay comprehensive.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

import html5lib

from licenselens.models import (
    STATUS_PLAIN_LABELS,
    Finding,
    FindingStatus,
    ScanResult,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.report.html import write_html_report
from licenselens.report.json_report import write_json_report
from tests.report_fixtures import comprehensive_report, empty_report, sparse_optional_fields_report

# ---------------------------------------------------------------------------
# Parsing helpers (html5lib + ElementTree — no extra dependency beyond html5lib)
# ---------------------------------------------------------------------------


def parse_html(html: str) -> ET.Element:
    """Parse HTML5 into a namespace-free ElementTree and return its root element."""
    tree = html5lib.parse(html, treebuilder="etree", namespaceHTMLElements=False)
    return tree.getroot() if hasattr(tree, "getroot") else tree  # type: ignore[return-value]


def _all(root: ET.Element, tag: str) -> list[ET.Element]:
    return list(root.iter(tag))


def _by_attr(root: ET.Element, attr: str, value: str | None = None) -> list[ET.Element]:
    return [
        e for e in root.iter() if attr in e.attrib and (value is None or e.attrib[attr] == value)
    ]


def _buttons_by_attr(root: ET.Element, attr: str) -> list[ET.Element]:
    """Filter *buttons* only — findings also carry ``data-workload``, so a bare
    attribute scan would wrongly treat finding articles as controls."""
    return [e for e in root.iter("button") if attr in e.attrib]


def _by_class(root: ET.Element, cls: str) -> list[ET.Element]:
    return [e for e in root.iter() if cls in (e.attrib.get("class") or "").split()]


def _local(el: ET.Element) -> str:
    """Local tag name: html5lib keeps SVG foreign-content elements namespaced
    (``{http://www.w3.org/2000/svg}svg``), so bare tag comparisons miss them.
    Comment/PI nodes carry a callable ``tag`` instead of a name."""
    tag = el.tag
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def text_of(el: ET.Element) -> str:
    """Full text content of an element subtree (mirrors ElementTree itertext)."""
    chunks: list[str] = []
    for node in el.iter():
        if node.text:
            chunks.append(node.text)
        if node.tail:
            chunks.append(node.tail)
    return "".join(chunks)


def render(result: ScanResult, tmp_path: Path) -> str:
    out = write_html_report(result, tmp_path / "report.html")
    return out.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# FIXTURE INTEGRITY (must stay green — guards the RED/GREEN split's meaning)
# ---------------------------------------------------------------------------

ALL_FINDING_STATUSES = {"gap", "partial", "ok", "not_licensed", "skipped", "error"}
ALL_WORKLOADS = {"identity", "defender", "sentinel", "purview", "endpoint", "general"}
ALL_EXPOSURE_CLASSES = {"none", "elevated", "exposed"}
ALL_CAPABILITY_OUTCOMES = {"fully_working", "needs_attention", "partly_set_up", "not_licensed"}


def test_comprehensive_fixture_covers_all_variants() -> None:
    result = comprehensive_report()
    assert {f.status.value for f in result.findings} == ALL_FINDING_STATUSES
    assert {f.exposure_class.value for f in result.findings} == ALL_EXPOSURE_CLASSES
    assert {o.status for o in result.capability_outcomes} == ALL_CAPABILITY_OUTCOMES
    assert len(result.capability_summaries) >= 4
    assert result.has_exposed is True
    assert result.exposed_check_ids == ["id-ca-priv-gaps"]
    assert len(result.moves) == 3
    assert any("<script>" in w for w in result.warnings)


def test_empty_fixture_is_truly_empty() -> None:
    result = empty_report()
    assert result.findings == []
    assert result.capability_summaries == []
    assert result.capability_outcomes == []
    assert result.moves == []
    assert result.capability_rollup.you_own == 0
    assert result.capability_rollup.realized_percent == 0
    assert result.has_exposed is False


# ---------------------------------------------------------------------------
# GROUP A — established invariants (formerly RED redesign contracts; the
# redesign has landed and these are now green regression guards)
# ---------------------------------------------------------------------------


def test_exposed_findings_are_surfaced_as_action_required(tmp_path: Path) -> None:
    # v2 folds the v1 "critical rail" into the gap status: an exposed finding is
    # rendered as a gap-status "Action required" article, and nothing renders
    # when nothing is exposed.
    result = comprehensive_report()
    assert result.has_exposed, "comprehensive fixture must set has_exposed=True"
    exposed_ids = set(result.exposed_check_ids)
    assert exposed_ids, "fixture must name exposed check ids"

    root = parse_html(render(result, tmp_path))
    gap_articles = [e for e in _by_attr(root, "data-status", "gap") if e.tag == "article"]
    assert gap_articles, "no gap-status findings rendered when has_exposed=True"

    for finding in result.findings:
        if finding.check_id in exposed_ids:
            assert any(finding.display_customer_title in text_of(a) for a in gap_articles), (
                f"exposed finding {finding.check_id!r} not surfaced as an action-required finding"
            )

    # No exposure -> no action-required findings.
    empty_root = parse_html(render(empty_report(), tmp_path))
    assert not [e for e in _by_attr(empty_root, "data-status", "gap") if e.tag == "article"], (
        "action-required findings must be absent when has_exposed=False"
    )


def test_capability_cards_expose_variant_signal(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    cards = _by_class(root, "card")
    assert cards, "no capability cards rendered"
    variants = {c.attrib.get("data-variant") for c in cards}
    assert all(c.attrib.get("data-variant") for c in cards), "a card is missing data-variant"
    assert {"needs_attention", "partly_set_up", "fully_working"} <= variants, (
        f"cards do not distinguish outcome variants: {sorted(v for v in variants if v)}"
    )


#: Future presentation words per finding status (HTML, not the JSON labels).
FUTURE_STATUS_LABELS = {
    "gap": "Action required",
    "partial": "Incomplete",
    "ok": "Operational",
    "not_licensed": "Not licensed",
    "skipped": "Not assessed",
    "error": "Verification failed",
}


def test_html_presentation_status_labels(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    for status, future_word in FUTURE_STATUS_LABELS.items():
        article = [e for e in _by_attr(root, "data-status", status) if e.tag == "article"]
        assert article, f"no finding article for status {status}"
        assert future_word in text_of(article[0]), (
            f"status {status} missing presentation label {future_word!r}"
        )


def test_filter_controls_are_accessibly_grouped(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    buttons = _buttons_by_attr(root, "data-filter") + _buttons_by_attr(root, "data-workload")
    assert buttons, "no filter controls found"
    groups = _by_attr(root, "role", "group")
    grouped_ids: set[int] = set()
    for group in groups:
        for node in group.iter():
            if "data-filter" in node.attrib or "data-workload" in node.attrib:
                grouped_ids.add(id(node))
    for button in buttons:
        assert id(button) in grouped_ids, "filter control not wrapped in a role=group"
    assert groups, "no role=group present"
    for group in groups:
        assert group.attrib.get("aria-label") or group.attrib.get("aria-labelledby"), (
            "role=group missing an accessible label"
        )


def test_live_count_region(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    regions = _by_attr(root, "role", "status")
    assert regions, "missing results-count region with role=status"
    region = regions[0]
    assert region.attrib.get("aria-live"), "count region missing aria-live"
    assert _by_attr(region, "data-visible-count"), "missing visible-count sub-element"
    assert _by_attr(region, "data-total-count"), "missing total-count sub-element"


def test_filter_buttons_expose_aria_pressed(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    buttons = _buttons_by_attr(root, "data-filter") + _buttons_by_attr(root, "data-workload")
    assert buttons, "no filter buttons found"
    for button in buttons:
        assert "aria-pressed" in button.attrib, "filter button missing aria-pressed"
        assert button.attrib["aria-pressed"] in ("true", "false"), (
            "aria-pressed must be 'true' or 'false'"
        )
    assert any(b.attrib["aria-pressed"] == "true" for b in buttons), (
        "no active filter button marked aria-pressed='true'"
    )


STOPWATCH_EMOJI = "\u23f1"  # U+23F1 — clock/stopwatch metadata glyph
BUSTS_EMOJI = "\U0001f465"  # U+1F465 — "busts in silhouette" metadata glyph
# U+25CF (●) is allowed as a typographic bullet and is intentionally not asserted.


def test_no_metadata_emoji(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    body_text = text_of(root)
    assert STOPWATCH_EMOJI not in body_text, "stopwatch emoji (U+23F1) must not appear"
    assert BUSTS_EMOJI not in body_text, "people emoji (U+1F465) must not appear"


# ---------------------------------------------------------------------------
# Warm-Charcoal (v2) design-signature contracts
# ---------------------------------------------------------------------------

SECTION_HEADINGS = [
    "Where you stand",
    "What you're paying for",
    "What matters most",
    "Why LicenseLens believes this",
]

TAGLINE = "Entitlements, controls, and configuration gaps."

LEGACY_HEADINGS = [
    "Security posture",
    "Licensed control inventory",
    "Priority actions",
    "Assessment findings",
    "Your security at a glance",
    "How to read this report",
    "What you already pay for",
    "Top things to do first",
    "Where you may not be getting the full benefit",
]
LEGACY_TAGLINE = "The security you already own (and ignore)"

VIOLET_TRIO = ("#9b8cff", "#b0a4ff", "#c7beff")
BRASS_HEXES = ("#b9a06a", "#cbb683", "#ddcca8", "#594818")

# Retired "Ink and Verdigris" tokens (DESIGN_V2.md §1: withdrawn, must not
# reappear). The report CSS must no longer declare any of these values.
RETIRED_INK_VERDIGRIS_TOKENS = (
    "--canvas: #0c1210",
    "--surface-1: #121a17",
    "--surface-2: #17201d",
    "--surface-3: #1e2925",
    "--surface-4: #26332e",
    "--accent: #8ad3b8",
)

# Warm Charcoal tokens (DESIGN_V2.md §2.1): the binding v2 palette. The exact
# declaration strings mirror the `:root` block in
# templates/report/v2/_v2_styles.css.j2.
WARM_CHARCOAL_TOKENS = (
    "--canvas: #191714",
    "--surface-1: #211E1A",
    "--surface-2: #2A2621",
    "--surface-3: #332E27",
    "--surface-4: #3D3730",
    "--accent: #E8DFC8",
    "--accent-hover: #F5EFDD",
    "--accent-focus: #FFF6E3",
    "--accent-print: #57482E",
)

SURFACE_TOKENS = (
    "--surface-1",
    "--surface-2",
    "--surface-3",
    "--surface-4",
)


def test_no_violet_accent_trio(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    for hex_value in VIOLET_TRIO:
        assert hex_value not in html, f"violet accent {hex_value!r} leaked into the report CSS"


def test_no_brass_accent_hexes(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    for hex_value in BRASS_HEXES:
        assert hex_value not in html, f"retired brass hex {hex_value!r} leaked into the report CSS"


def test_no_radial_gradient_backdrop(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    assert "radial-gradient" not in html, "radial-gradient hero glow must be removed"


def test_no_color_mix_usage(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    assert "color-mix(" not in html, "color-mix() usage must be removed"


def test_radii_use_only_declared_stops(tmp_path: Path) -> None:
    """DESIGN_V2 §4 radius stops: 0/2/6/10/16 and the 999px pill (authorized
    ONLY for proportion-based fills and constellation node circles). Non-stop
    radii (4px, 12px) and the undeclared 50% circle must never appear; the
    pill stop must be present for the authorized fills."""
    html = render(comprehensive_report(), tmp_path)
    assert "border-radius: 12px" not in html, "12px radius is not a §4 stop"
    assert "border-radius: 4px" not in html, "4px radius is not a §4 stop"
    assert "border-radius: 50%" not in html, "50% circle is not a §4 stop (use 999px)"
    assert "border-radius:50%" not in html, "unspaced circular radius must go"
    assert "border-radius: 999px" in html, "pill radius (999px) must authorize proportion fills"


def test_warm_charcoal_tokens_present(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    for token in WARM_CHARCOAL_TOKENS:
        assert token in html, f"v2 token {token!r} missing from the report CSS"


def test_retired_ink_verdigris_tokens_absent(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    for token in RETIRED_INK_VERDIGRIS_TOKENS:
        assert token not in html, f"withdrawn Ink-and-Verdigris token {token!r} still present"


def test_every_surface_token_is_consumed(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    for token in SURFACE_TOKENS:
        assert f"{token}:" in html, f"surface token {token!r} not declared"
        assert f"var({token})" in html, f"surface token {token!r} is declared but never consumed"


def test_status_glyphs_are_pairwise_distinct_inline_svgs(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    shapes: dict[str, str] = {}
    for status in ("gap", "partial", "ok", "not_licensed", "skipped", "error"):
        match = re.search(
            rf'class="status-marker {status}">\s*(<svg[\s\S]*?</svg>)',
            html,
        )
        assert match, f"missing inline SVG glyph for status {status!r}"
        svg = match.group(1)
        assert 'aria-hidden="true"' in svg, f"glyph for {status!r} missing aria-hidden"
        shapes[status] = svg
    assert shapes["ok"] != shapes["not_licensed"], "ok and not_licensed glyphs must differ"
    assert len(set(shapes.values())) == 6, "all six status glyphs must be pairwise distinct"


def test_sparse_optional_fields_render_without_crash(tmp_path: Path) -> None:
    html = render(sparse_optional_fields_report(), tmp_path)
    assert "Sparse optional fields" in html
    assert "Not reported" in html or "None reported" in html or "Sparse capability" in html
    assert "Open Microsoft admin page" not in html


def test_section_heading_order(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    h2_texts = [text_of(h).strip() for h in _all(root, "h2")]
    for heading in SECTION_HEADINGS:
        assert heading in h2_texts, f"missing section heading {heading!r}"
    positions = [h2_texts.index(h) for h in SECTION_HEADINGS]
    assert positions == sorted(positions), f"section headings out of order: {h2_texts}"


def test_security_ledger_section_headings_exact(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    h2_texts = [text_of(h).strip() for h in _all(root, "h2")]
    for heading in SECTION_HEADINGS:
        assert heading in h2_texts, f"missing security-ledger section heading {heading!r}"
    for legacy in LEGACY_HEADINGS:
        assert legacy not in h2_texts, f"legacy heading {legacy!r} still present in the report"


def test_technical_details_is_summary_not_heading(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    summaries = [text_of(s).strip() for s in _all(root, "summary")]
    assert any("Technical details (product names, SKUs, check IDs)" in s for s in summaries), (
        "technical details summary label missing from the report"
    )
    h2_texts = [text_of(h).strip() for h in _all(root, "h2")]
    assert not any("Technical details" in h for h in h2_texts), (
        "technical details must be a <summary>, not an h2"
    )


def test_security_ledger_tagline(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    assert TAGLINE in html, "security-ledger tagline missing from the report"
    assert LEGACY_TAGLINE not in html, "legacy tagline still rendered in the report"


def test_legacy_dashboard_copy_absent(tmp_path: Path) -> None:
    html = render(comprehensive_report(), tmp_path)
    for legacy in [*LEGACY_HEADINGS, LEGACY_TAGLINE]:
        assert legacy not in html, f"legacy dashboard copy {legacy!r} still rendered"


# ---------------------------------------------------------------------------
# GROUP B — invariants that MUST PASS today (regression guards)
# ---------------------------------------------------------------------------


def test_exactly_one_main_and_heading_hierarchy(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    mains = _all(root, "main")
    assert len(mains) == 1, f"expected exactly one <main>, found {len(mains)}"
    # Brief §25: exactly one document title — a second <h1> (e.g. a per-section
    # brand heading) breaks the report's single-document-title contract.
    h1s = _all(root, "h1")
    assert len(h1s) == 1, f"expected exactly one <h1>, found {len(h1s)}"
    headings = [e for e in root.iter() if e.tag in {"h1", "h2", "h3", "h4", "h5", "h6"}]
    assert headings, "no headings found"
    levels = [int(e.tag[1]) for e in headings]
    assert levels[0] == 1, "first heading is not an h1"
    for prev, cur in zip(levels, levels[1:], strict=False):
        assert cur <= prev + 1, f"heading level skipped from h{prev} to h{cur}"


def test_valid_html5_parse(tmp_path: Path) -> None:
    # "Parses without error" = the canonical html5lib.parse() completes and yields
    # a coherent document tree (html5lib is a lenient, spec-error-recovery parser
    # by design; HTMLParser(strict=True) is a separate opt-in API that raises).
    root = parse_html(render(comprehensive_report(), tmp_path))
    assert root.tag == "html", f"expected <html> root, got {root.tag!r}"
    assert any(e.tag == "head" for e in root), "missing <head>"
    assert any(e.tag == "body" for e in root), "missing <body>"


def test_no_external_resource_references(tmp_path: Path) -> None:
    result = comprehensive_report()
    html = render(result, tmp_path)
    lowered = html.lower()
    assert "<link" not in lowered, "found an external stylesheet <link>"
    assert "@import" not in lowered, "found CSS @import"
    assert "url(http" not in lowered, "found CSS url(http...) reference"
    root = parse_html(html)
    assert not [e for e in root.iter("script") if "src" in e.attrib], "found <script src=...>"
    assert not list(root.iter("img")), "found an <img>"
    # The only https:// URLs allowed are the static Microsoft admin deep_links.
    urls = set(re.findall(r"https://[^\s\"'<>]+", html))
    allowed = {f.deep_link for f in result.findings if f.deep_link}
    assert urls <= allowed, f"unexpected external URL(s): {urls - allowed}"


def test_dom_hooks_preserved(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    findings = _by_class(root, "finding")
    assert findings, "no .finding articles"
    assert all(f.tag == "article" for f in findings), "finding hooks are not <article>"
    for finding in findings:
        assert finding.attrib.get("data-status") in ALL_FINDING_STATUSES, (
            "finding missing a valid data-status"
        )
        assert finding.attrib.get("data-workload") in ALL_WORKLOADS, (
            "finding missing a valid data-workload"
        )
    assert _by_attr(root, "data-filter"), "no [data-filter] buttons"
    assert _by_attr(root, "data-workload"), "no [data-workload] buttons"


def test_json_serialized_enum_values_unchanged(tmp_path: Path) -> None:
    result = comprehensive_report()
    out = write_json_report(result, tmp_path / "report.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    statuses = [f["status"] for f in data["findings"]]
    assert set(statuses) == ALL_FINDING_STATUSES, (
        f"serialized status enum values changed: {set(statuses)}"
    )
    for finding in data["findings"]:
        assert finding["status_label"] == STATUS_PLAIN_LABELS[finding["status"]], (
            f"status_label drifted from STATUS_PLAIN_LABELS for {finding['status']}"
        )


# ---------------------------------------------------------------------------
# Single-file workload-icon render contract (DESIGN_V2.md §12, amended)
# ---------------------------------------------------------------------------
#
# Verified against the vendored upstream tree (loryanstrant/MicrosoftCloudLogos)
# at pinned commit fc3a6c9506dc9a6ebdfb4f5891ee486f2717257c: brand SVGs exist
# for only six of the twelve marks there. In report workload-key space (the
# values the rendered HTML carries in ``data-workload``, via the pinned
# ``REPORT_WORKLOAD_TO_ICON_KEY`` mapping), the split is:

SVG_VENDORED_WORKLOADS = frozenset(
    {
        "identity",  # entra-id
        "intune",  # intune
        "sentinel",  # microsoft-sentinel
        "purview",  # purview
        "power_platform",  # power-platform
        "power_bi",  # power-bi
    }
)
PNG_ONLY_WORKLOADS = frozenset(
    {
        "defender",  # defender mark is PNG-only upstream
        "endpoint",  # maps to the defender mark — PNG-only upstream
        "exchange",  # exchange
        "collaboration",  # sharepoint
        "teams",  # teams
        "azure",  # azure
    }
)
# ``onedrive`` is PNG-only upstream but is not a report workload and never renders.
PNG_ONLY_LABELS = {
    "defender": "Defender",
    "endpoint": "Endpoint",
    "exchange": "Exchange",
    "collaboration": "Collaboration",
    "teams": "Teams",
    "azure": "Azure",
}


def _inline_marks_in(root: ET.Element, workload: str) -> list[ET.Element]:
    """Inline ``workload-icon`` svg elements inside any element carrying
    ``data-workload="<workload>"`` (chart rows, constellation captions, cards)."""
    marks: list[ET.Element] = []
    for holder in root.iter():
        if holder.attrib.get("data-workload") != workload:
            continue
        marks.extend(
            el
            for el in holder.iter()
            if _local(el) == "svg"
            and "workload-icon" in (el.attrib.get("class") or "").split()
        )
    return list({id(mark): mark for mark in marks}.values())


def test_single_file_inlines_svg_only_for_svg_vendored_marks(tmp_path: Path) -> None:
    """Lock the single-file workload-icon render contract (DESIGN_V2.md §12, amended).

    At pinned upstream commit fc3a6c9506dc9a6ebdfb4f5891ee486f2717257c only six
    of the twelve MicrosoftCloudLogos marks ship an SVG. So the single-file
    report inlines ``<svg class="workload-icon">`` ONLY for SVG-vendored
    workloads — six inline, six text-label-only (no data-URI, no hotlink, no
    inline svg for the PNG-only set). The bundle's hashed ``<img>`` rendering
    of all twelve is covered elsewhere (test_report_hardening_browser.py).
    """
    root = parse_html(render(comprehensive_report(), tmp_path))

    present = {el.attrib["data-workload"] for el in _by_attr(root, "data-workload")}
    svg_marks = _by_class(root, "workload-icon")
    assert svg_marks, "single-file render lost every inline workload mark"
    assert all(_local(el) == "svg" for el in svg_marks), (
        "workload-icon must be an inline <svg> in the single-file report, never <img>"
    )

    svg_present = present & SVG_VENDORED_WORKLOADS
    assert svg_present, "fixture must exercise at least one SVG-vendored workload"
    for workload in sorted(svg_present):
        marks = _inline_marks_in(root, workload)
        assert marks, (
            f"SVG-vendored workload {workload!r} rendered without an inline workload-icon"
        )

    png_present = present & PNG_ONLY_WORKLOADS
    assert png_present, "fixture must exercise at least one PNG-only workload"
    for workload in sorted(png_present):
        assert not _inline_marks_in(root, workload), (
            f"PNG-only workload {workload!r} must not inline a workload-icon svg"
        )
        rows = [
            el
            for el in root.iter("div")
            if el.attrib.get("data-workload") == workload
            and "chart-row" in (el.attrib.get("class") or "").split()
        ]
        assert rows, f"PNG-only workload {workload!r} missing its findings-by-workload row"
        assert any(PNG_ONLY_LABELS[workload] in text_of(row) for row in rows), (
            f"PNG-only workload {workload!r} lost its visible text label"
        )


# ---------------------------------------------------------------------------
# Single-file a11y sibling-overlay contract (F2 major #1 fix)
# ---------------------------------------------------------------------------


def test_single_file_no_interactive_inside_role_img(tmp_path: Path) -> None:
    """Lock the a11y restructure: ARIA ``img`` has presentational children, so
    no interactive element may be a descendant of any ``[role="img"]`` layer.

    The cross-filter buttons now live in sibling ``.dist-hits`` / ``.chart-hits``
    overlay layers (aligned by ``alignChartHits()``); the ``role="img"`` visual
    layers (``.dist-bar``, ``.chart-body``, radial gauge) hold spans only.
    """
    root = parse_html(render(comprehensive_report(), tmp_path))
    visual_layers = _by_attr(root, "role", "img")
    assert visual_layers, "no role=img visual layers found"
    offenders = [el for layer in visual_layers for el in layer.iter() if el.tag in {"button", "a"}]
    assert not offenders, (
        "interactive element nested inside [role=img] (presentational children "
        "would flatten it out of the accessibility tree)"
    )

    # Positive half: the cross-filter buttons still exist, in the sibling layers.
    for layer_class in ("dist-hits", "chart-hits"):
        layers = _by_class(root, layer_class)
        assert layers, f"missing sibling {layer_class} overlay layer"
        assert any(list(layer.iter("button")) for layer in layers), (
            f"{layer_class} overlay holds no cross-filter buttons"
        )


def test_single_file_chart_hits_never_paint(tmp_path: Path) -> None:
    """Lock the overlay paint contract (F2 major #2 fix): the cross-filter
    hit buttons must NEVER paint — they carry only ``.chart-hit`` /
    ``.dist-hit``, never the visual paint classes (``.chart-bar`` /
    ``.dist-segment`` / ``status-*``), and the inline style block declares
    ``background: transparent`` for the hit layer. The proportional spans
    stay the sole painted surface, so bar length ∝ count (the previous
    build let the buttons inherit the paint classes and rendered opaque
    full-track bars over the partial bars — Chromium measured visual bar
    166px vs hit 331px, both painted ``rgb(158,152,140)``).

    Also locks facet parity: each hit's ``data-chart-toggle`` mirrors its
    figure's visual rows/segments one-for-one and in order, so
    ``alignChartHits()`` pairs them correctly.
    """
    html = render(comprehensive_report(), tmp_path)
    root = parse_html(html)

    # 1. Hit buttons carry no paint classes and stay toggle-ready.
    hits = _buttons_by_attr(root, "data-chart-toggle")
    assert hits, "single-file render lost every cross-filter hit button"
    for hit in hits:
        classes = set((hit.attrib.get("class") or "").split())
        assert {"chart-hit", "dist-hit"} & classes, (
            "hit button must carry .chart-hit or .dist-hit"
        )
        assert not {"chart-bar", "dist-segment"} & classes, (
            "hit button carries a paint class (.chart-bar/.dist-segment) — "
            "the foundation would paint it opaque over the proportional bar"
        )
        assert not any(c.startswith("status-") for c in classes), (
            "hit button carries a status-* paint class"
        )
        assert hit.attrib.get("aria-pressed") == "false"

    # 2. The hit layer declares transparent paint in the inline style block.
    style_text = "\n".join(text_of(el) for el in root.iter("style"))
    rule = re.search(
        r"\.chart-hit,\s*\.dist-hit\s*\{(?P<body>.*?)\}", style_text, re.DOTALL
    )
    assert rule, "inline style block lost the .chart-hit/.dist-hit rule"
    assert "background: transparent" in rule.group("body"), (
        "hit layer must declare background: transparent"
    )
    assert "border: 1px solid transparent" in rule.group("body"), (
        "hit layer must keep a transparent border for the hover/pressed affordance"
    )

    # 3. Facet parity: chart hits mirror their figure's visual rows, in order.
    facet_attr = {
        "chart-status": "data-status",
        "chart-workload": "data-workload",
        "chart-severity": "data-severity",
    }
    for fig in root.iter("figure"):
        attr = facet_attr.get(fig.attrib.get("id") or "")
        if attr is None:
            continue
        rows = [
            el
            for el in fig.iter("div")
            if "chart-row" in (el.attrib.get("class") or "").split()
        ]
        layers = [
            el
            for el in fig.iter("div")
            if "chart-hits" in (el.attrib.get("class") or "").split()
        ]
        assert len(layers) == 1, f"{fig.attrib['id']}: expected one .chart-hits layer"
        visual_facets = [
            f"{fig.attrib['id'].removeprefix('chart-')}:{row.attrib[attr]}" for row in rows
        ]
        hit_facets = [b.attrib["data-chart-toggle"] for b in layers[0].iter("button")]
        assert hit_facets == visual_facets, (
            f"{fig.attrib['id']}: hit toggle facets {hit_facets} out of sync "
            f"with visual rows {visual_facets}"
        )

    # Dist bar: hit facets == visible segment status classes, in order.
    dist_figs = [
        el
        for el in root.iter("figure")
        if "dist-figure" in (el.attrib.get("class") or "").split()
    ]
    assert len(dist_figs) == 1, "expected one .dist-figure"
    dist_fig = dist_figs[0]
    segments = [
        c
        for el in dist_fig.iter("span")
        if "dist-segment" in (el.attrib.get("class") or "").split()
        for c in (el.attrib.get("class") or "").split()
        if c.startswith("status-")
    ]
    dist_layers = [
        el
        for el in dist_fig.iter("div")
        if "dist-hits" in (el.attrib.get("class") or "").split()
    ]
    assert len(dist_layers) == 1, "expected one .dist-hits layer"
    dist_hits = [b.attrib["data-chart-toggle"] for b in dist_layers[0].iter("button")]
    assert dist_hits == [f"status:{s.removeprefix('status-')}" for s in segments], (
        f"dist-hit toggles {dist_hits} out of sync with segments {segments}"
    )


# ---------------------------------------------------------------------------
# Single-file offline / zero-external contract (string-level trio)
# ---------------------------------------------------------------------------


def test_single_file_zero_network_and_zero_img(tmp_path: Path) -> None:
    """Lock the single-file offline contract: zero ``<img>`` tags, zero
    ``http://`` strings (inline SVGs render with their ``xmlns`` URL stripped),
    and exactly one inline ``<script>``.

    The parsed no-``<img>`` and one-``<script>`` halves partially overlap
    ``test_no_external_resource_references`` and
    ``test_baseline_sections_and_no_injected_element``; this test pins the trio
    as one string-level contract — notably the zero-``http://`` lock, which no
    other test asserts.
    """
    html = render(comprehensive_report(), tmp_path)
    assert "<img" not in html, "single-file report must not emit any <img> tag"
    assert "http://" not in html, (
        "single-file report must not reference any http:// URL (inline SVG xmlns stripped)"
    )
    assert html.count("<script") == 1, "single-file report must carry exactly one inline <script>"


# ---------------------------------------------------------------------------
# Constellation status-color cascade locks (design-v2 brief conformance,
# todo 1). The `.status-*` single-class rules must WIN the cascade against
# `.constellation-point` and `.constellation-legend-chip` bases so the status
# color is present server-side (zero JS, zero animation dependency). These
# assertions run against the RENDERED single-file HTML: they are the drift
# tripwire — re-adding a `color:` to the point base or dropping the two-class
# legend rules must fail here.
# ---------------------------------------------------------------------------

CONSTELLATION_STATUS_VARIANTS = ("gap", "partial", "ok", "not_licensed", "skipped", "error")


def _style_text(html: str) -> str:
    """Concatenated text of every inline <style> block in the rendered output."""
    root = parse_html(html)
    return "\n".join(text_of(el) for el in root.iter("style"))


def test_constellation_cascade_point_base_has_no_color(tmp_path: Path) -> None:
    """The `.constellation-point` base block must carry NO `color:` declaration.

    A base `color: var(--state-neutral)` (same specificity, later in source)
    beats the earlier `.status-*` rules and greys every node — the committed
    report-hero screenshot bug. The base block keeps layout only; static
    status color comes from the shared `.status-*` classes.
    """
    style = _style_text(render(comprehensive_report(), tmp_path))
    match = re.search(r"\.constellation-point\s*\{(?P<body>[^{}]*)\}", style)
    assert match, "missing .constellation-point base block in the rendered CSS"
    assert "color:" not in match.group("body"), (
        ".constellation-point base block declares a color and will beat the "
        ".status-* classes in the cascade: "
        f"{match.group('body').strip()}"
    )


def test_constellation_cascade_legend_two_class_rules_present(tmp_path: Path) -> None:
    """A `.constellation-legend-chip.status-<variant>` two-class rule must exist
    for every legend variant (gap/partial/ok/not_licensed/skipped/error).

    The chip base block's `color: var(--text-2)` beats the single-class
    `.status-*` rules (same specificity, later in source); only the two-class
    pair (0,2,0) restores the status color on the legend swatch.
    """
    style = _style_text(render(comprehensive_report(), tmp_path))
    for variant in CONSTELLATION_STATUS_VARIANTS:
        assert f".constellation-legend-chip.status-{variant}" in style, (
            f"missing two-class legend rule for status {variant!r}"
        )


def test_constellation_cascade_instant_final_state_rule(tmp_path: Path) -> None:
    """`body.instant .constellation-point` must exist and resolve color via
    `--resolve-to` — the reduced-motion/instant final state (DESIGN_V2 §11)."""
    style = _style_text(render(comprehensive_report(), tmp_path))
    match = re.search(r"body\.instant \.constellation-point\s*\{(?P<body>[^{}]*)\}", style)
    assert match, "missing body.instant .constellation-point rule in the rendered CSS"
    body = match.group("body")
    assert "color:" in body, "body.instant rule must declare the final node color"
    assert "var(--resolve-to" in body, (
        "body.instant rule must resolve the status color via --resolve-to: "
        f"{body.strip()}"
    )


# ---------------------------------------------------------------------------
# Finding-card meta single-source + empty-evidence fallback locks
# (design-v2 brief conformance, todo 8). Severity / Scope / Confidence each
# render exactly once per finding article — in the header meta row — and empty
# evidence values render the literal "None reported" fallback (same wording as
# the Limitations fallback) instead of a bare `<code>key</code>:`.
# ---------------------------------------------------------------------------

META_SINGLE_SOURCE_KEYS = ("Severity", "Scope", "Confidence")


def _finding_article_chunks(html: str) -> list[str]:
    """One chunk per complete finding article: everything between its opening
    ``<article class="finding ...">`` tag and the matching ``</article>``
    (finding bodies contain no nested articles)."""
    chunks = re.findall(r'<article class="finding [^>]*>.*?</article>', html, re.DOTALL)
    assert chunks, "no finding articles rendered"
    return chunks


def test_meta_keys_single_source_per_finding_article(tmp_path: Path) -> None:
    """Severity, Scope, and Confidence appear exactly ONCE per finding article,
    in the header meta-key span — the Why-it-matters belief-meta repeats
    (Severity/Scope) and the tech-body Confidence line are gone."""
    result = comprehensive_report()
    html = render(result, tmp_path)
    chunks = _finding_article_chunks(html)
    assert len(chunks) == len(result.findings), (
        f"expected {len(result.findings)} finding articles, split into {len(chunks)}"
    )
    for chunk in chunks:
        assert chunk.strip(), "empty finding article body"
    for key in META_SINGLE_SOURCE_KEYS:
        for chunk in chunks:
            count = chunk.count(f">{key}:")
            assert count == 1, (
                f"{key!r} appears {count} times in one finding article — "
                "it must be single-sourced in the header meta row"
            )
            assert f'meta-key">{key}:' in chunk, (
                f"{key!r} single occurrence is not the header meta-key span"
            )


def test_empty_evidence_values_render_none_reported(tmp_path: Path) -> None:
    """Empty evidence values (None, "", [], {}) render the literal
    "None reported" fallback — never a bare `<code>key</code>` followed by
    whitespace and `</li>` with no value after the colon."""
    result = empty_report()
    result.findings = [
        Finding(
            check_id="empty-evidence",
            title="Empty evidence values",
            workload=Workload.IDENTITY,
            status=FindingStatus.GAP,
            severity=Severity.HIGH,
            value_impact=ValueImpact.HIGH,
            summary="Evidence keys whose values are empty.",
            customer_title="Empty evidence values",
            customer_summary="Empty evidence values.",
            customer_next_step="",
            confidence_label="Medium confidence",
            data_sources=[],
            limitations=[],
            evidence={"enforced_policies": [], "note": ""},
        )
    ]
    html = render(result, tmp_path)

    for key in ("enforced_policies", "note"):
        assert f"<code>{key}</code>: None reported" in html, (
            f"empty evidence key {key!r} did not render the 'None reported' fallback"
        )
        assert re.search(rf"<code>{key}</code>:\s*</li>", html) is None, (
            f"evidence key {key!r} rendered bare — nothing after the colon"
        )


# ---------------------------------------------------------------------------
# Brief §25 media-query string locks (design-v2 brief conformance, todo 10).
# The single-file render must ship the print stylesheet block and the
# reduced-motion instant final state — as literal strings, so a template
# drift that drops either media query fails here without a browser.
# ---------------------------------------------------------------------------


def test_single_file_inlines_print_media_query(tmp_path: Path) -> None:
    """Brief §25: the rendered single-file report contains the literal
    ``@media print`` block (the offline print stylesheet is inlined)."""
    html = render(comprehensive_report(), tmp_path)
    assert "@media print" in html, (
        "single-file report lost its inline @media print block"
    )


def test_single_file_inlines_reduced_motion_media_query(tmp_path: Path) -> None:
    """Brief §25: the rendered single-file report carries the
    ``prefers-reduced-motion`` contract — the CSS ``@media
    (prefers-reduced-motion: reduce)`` block AND the reveal script's
    ``window.matchMedia`` check must both survive rendering."""
    html = render(comprehensive_report(), tmp_path)
    assert "prefers-reduced-motion" in html, (
        "single-file report lost its prefers-reduced-motion contract (CSS or JS)"
    )

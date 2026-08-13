"""Structural render contracts for the Security License Lens HTML report.

Two groups, deliberately partitioned:

* **GROUP A — RED redesign contracts**: new contracts the upcoming redesign must
  satisfy. They *fail today* against the current template, and must fail as
  assertion errors (never import/fixture errors).
* **GROUP B — invariants that must PASS today**: regression guards locking the
  current behavior so the redesign cannot silently break it.

A small FIXTURE-INTEGRITY preamble asserts the fixtures themselves stay
comprehensive; if those ever pass vacuously the RED/GREEN split loses meaning.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

import html5lib

from licenselens.models import STATUS_PLAIN_LABELS, ScanResult
from licenselens.report.html import write_html_report
from licenselens.report.json_report import write_json_report
from tests.report_fixtures import comprehensive_report, empty_report

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
# GROUP A — RED redesign contracts (must fail against the current template)
# ---------------------------------------------------------------------------


def test_critical_rail_region_gated_on_exposure(tmp_path: Path) -> None:
    result = comprehensive_report()
    assert result.has_exposed, "comprehensive fixture must set has_exposed=True"
    root = parse_html(render(result, tmp_path))
    rail = _by_attr(root, "data-critical-rail")
    assert rail, "critical rail region missing when has_exposed=True"
    rail_text = text_of(rail[0])
    exposed_titles = [
        f.display_customer_title for f in result.findings if f.check_id in result.exposed_check_ids
    ]
    assert exposed_titles, "fixture has no exposed findings"
    for title in exposed_titles:
        assert title in rail_text, f"rail text missing exposed finding title {title!r}"

    # The rail must be absent when nothing is exposed.
    empty_root = parse_html(render(empty_report(), tmp_path))
    assert not _by_attr(empty_root, "data-critical-rail"), (
        "critical rail must be absent when has_exposed=False"
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
# GROUP B — invariants that MUST PASS today (regression guards)
# ---------------------------------------------------------------------------

SECTION_HEADINGS = [
    "Your security at a glance",
    "What you already pay for",
    "Top things to do first",
    "Where you may not be getting the full benefit",
]


def test_section_heading_order(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    h2_texts = [text_of(h).strip() for h in _all(root, "h2")]
    for heading in SECTION_HEADINGS:
        assert heading in h2_texts, f"missing section heading {heading!r}"
    positions = [h2_texts.index(h) for h in SECTION_HEADINGS]
    assert positions == sorted(positions), f"section headings out of order: {h2_texts}"


def test_exactly_one_main_and_heading_hierarchy(tmp_path: Path) -> None:
    root = parse_html(render(comprehensive_report(), tmp_path))
    mains = _all(root, "main")
    assert len(mains) == 1, f"expected exactly one <main>, found {len(mains)}"
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

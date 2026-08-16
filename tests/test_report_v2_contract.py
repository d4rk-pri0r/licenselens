"""v2 report surface contract tests (todo 14).

Covers the NEW v2 surface not already locked elsewhere: ``test_report_viewmodel``
owns belief-block field binding + determinism, and ``test_report_render`` owns the
DOM/design signature. This file adds six contracts over the same frozen fixtures:

1. Constellation determinism + exact entry shape + workload ordering.
2. Belief-block labels render in HTML and are bound to fixture data (never
   hardcoded), with "Admin destination" conditional on ``deep_link``.
3. Posture is data-driven: the rendered percent flows from the model, never a
   literal, and differs across fixtures.
4. Motion / reduced-motion contract in the real offline bundle (browser):
   reduced motion shows the digits instantly with no reveal classes; default
   motion reveals.
5. ``app.js`` binds ``realized_percent`` from data and never hardcodes a
   percent literal.
6. The three belief prose slots (summary line, Expected, Observed) stay
   distinct in the rendered HTML: Expected never equals Observed, and no two
   adjacent belief paragraphs within one article are byte-identical.
"""

from __future__ import annotations

import html as html_lib
import re
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page

from licenselens.catalog.expected_states import expected_state_map
from licenselens.models import (
    BlastRadius,
    CapabilityRollup,
    Finding,
    FindingStatus,
    ScanResult,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.paths import templates_dir
from licenselens.report.bundle import build_report_bundle
from licenselens.report.html import write_html_report
from licenselens.report.viewmodel import build_constellation
from licenselens.schema_contracts import EvaluationMode
from tests.report_fixtures import (
    comprehensive_report,
    empty_report,
    sparse_optional_fields_report,
)

# ---------------------------------------------------------------------------
# Small shared helpers (self-contained; no import of other test modules)
# ---------------------------------------------------------------------------


def _render(result: ScanResult, tmp_path: Path) -> str:
    """Render one report to HTML via the real writer and return its text."""
    return write_html_report(result, tmp_path / "report.html").read_text(encoding="utf-8")


# The constellation's workload priority order (mirrors the view-model contract).
_WORKLOAD_PRIORITY: tuple[str, ...] = (
    "identity",
    "endpoint",
    "defender",
    "sentinel",
    "purview",
    "exchange",
    "collaboration",
    "teams",
    "power_platform",
    "power_bi",
    "intune",
    "azure",
)


def _workload_rank(workload: str | None) -> int:
    """Rank a workload by priority; unknown/absent workloads sort last."""
    if workload is None or workload not in _WORKLOAD_PRIORITY:
        return len(_WORKLOAD_PRIORITY)
    return _WORKLOAD_PRIORITY.index(workload)


_EXPECTED_CONSTELLATION_KEYS = frozenset(
    {"id", "name", "plain_name", "status", "status_label", "workload", "related_check_ids"}
)


# ---------------------------------------------------------------------------
# 1. Constellation determinism + structure
# ---------------------------------------------------------------------------


def test_constellation_deterministic_and_structured() -> None:
    """``build_constellation`` is deterministic and yields the exact v2 entry shape.

    Two calls on the same fixture are equal; every entry carries exactly the seven
    keys the B-section partial consumes; and entries are ordered by workload
    priority then ``plain_name`` (ties) so the first entry's workload is one of the
    declared priorities.
    """
    result = comprehensive_report()
    first = build_constellation(result)
    second = build_constellation(result)
    assert first == second, "build_constellation is not deterministic over identical input"
    assert first, "comprehensive fixture must resolve at least one constellation entry"
    for entry in first:
        assert set(entry.keys()) == _EXPECTED_CONSTELLATION_KEYS, (
            f"constellation entry has unexpected keys: {sorted(entry.keys())}"
        )
    assert first[0]["workload"] in _WORKLOAD_PRIORITY, (
        f"first entry workload {first[0]['workload']!r} not a declared priority"
    )
    ranks = [_workload_rank(entry["workload"]) for entry in first]
    assert ranks == sorted(ranks), "constellation not ordered by workload priority"
    for index in range(len(first) - 1):
        if ranks[index] == ranks[index + 1]:
            assert first[index]["plain_name"] <= first[index + 1]["plain_name"], (
                "constellation tie not ordered by plain_name"
            )


# ---------------------------------------------------------------------------
# 2. Belief-block labels render in HTML and bind to data
# ---------------------------------------------------------------------------

_BELIEF_LABELS = ("Expected", "Observed", "Why it matters", "Recommended action", "Evidence")


def test_belief_block_labels_render_and_bind_to_data(tmp_path: Path) -> None:
    """The D-section belief-block labels render and are bound to fixture data.

    The five static labels always appear; "Admin destination" appears because every
    comprehensive finding carries a ``deep_link``; and the fixture's actual prose
    (``customer_summary`` for the summary line, the catalog ``expected_state`` for
    the Expected slot, and ``summary`` for the Observed slot) appears in the
    rendered HTML for the first finding.
    """
    result = comprehensive_report()
    html = _render(result, tmp_path)
    for label in _BELIEF_LABELS:
        assert label in html, f"belief-block label {label!r} missing from the rendered report"
    assert "Admin destination" in html, "admin-destination slot missing when deep_link present"
    finding = result.findings[0]
    assert finding.customer_next_step in html, (
        "recommended-action slot is not bound to customer_next_step"
    )
    assert finding.summary in html, "observed slot is not bound to the finding summary"
    assert finding.customer_summary in html, (
        "summary line is not bound to the finding customer_summary"
    )
    assert expected_state_map()[finding.check_id] in html, (
        "expected slot is not bound to the catalog expected_state"
    )


def test_admin_destination_absent_without_deep_link(tmp_path: Path) -> None:
    """A finding with no ``deep_link`` renders no "Admin destination" slot."""
    html = _render(sparse_optional_fields_report(), tmp_path)
    assert "Admin destination" not in html, (
        "admin-destination slot rendered for a finding with no deep_link"
    )


def _article_chunks(rendered: str) -> list[str]:
    """Split rendered HTML into one chunk per complete finding article."""
    return re.findall(r'<article class="finding [^>]*>.*?</article>', rendered, re.DOTALL)


def _plain(text: str) -> str:
    """Strip tags/entities and collapse whitespace from a rendered fragment."""
    text = re.sub(r"<[^>]+>", "", text)
    return " ".join(html_lib.unescape(text).split())


def _belief_slot_text(chunk: str, label: str) -> str:
    """Return the normalized paragraph text of one belief slot in an article."""
    pattern = re.compile(
        r'<div class="belief-slot">\s*<span class="belief-label">'
        + re.escape(label)
        + r"</span>\s*<p>(.*?)</p>",
        re.DOTALL,
    )
    match = pattern.search(chunk)
    assert match is not None, f"belief slot {label!r} not found in the finding article"
    return _plain(match.group(1))


def test_belief_prose_slots_are_distinct(tmp_path: Path) -> None:
    """The summary line, Expected, and Observed stay three different sentences.

    For every finding article of the comprehensive fixture: the rendered Expected
    text differs from the rendered Observed text (for skipped/"Not assessed"
    findings the Observed slot is replaced by "Why this was skipped" — todo 21),
    and no two adjacent belief paragraphs within one article are byte-identical
    after normalization.
    """
    result = comprehensive_report()
    rendered = _render(result, tmp_path)
    chunks = _article_chunks(rendered)
    assert len(chunks) == len(result.findings), (
        f"expected one article per finding, got {len(chunks)} chunks for "
        f"{len(result.findings)} findings"
    )
    for chunk, finding in zip(chunks, result.findings, strict=True):
        expected = _belief_slot_text(chunk, "Expected")
        observed_label = (
            "Why this was skipped" if finding.status == FindingStatus.SKIPPED else "Observed"
        )
        observed = _belief_slot_text(chunk, observed_label)
        assert expected != observed, (
            f"Expected and {observed_label} collapsed to the same sentence for "
            f"{finding.check_id}: {expected!r}"
        )
        paragraphs = [
            _plain(match) for match in re.findall(r"<p\b[^>]*>(.*?)</p>", chunk, re.DOTALL)
        ]
        for left, right in zip(paragraphs, paragraphs[1:], strict=False):
            assert left != right, (
                f"adjacent identical belief paragraphs for {finding.check_id}: {left!r}"
            )


# The todo-12 follow-up: four checks once carried expected_state copy that was
# byte-identical to the evaluator's ok summary, so compliant findings rendered
# Expected == Observed. The renderer is correct (Expected binds the catalog,
# Observed binds the finding summary) — this locks the rendered slots for those
# exact compliant findings.
_OK_FINDING_SUMMARIES: dict[str, str] = {
    "exo-smtp-auth-disabled": "SMTP AUTH is disabled at the organization level.",
    "teams-anonymous-start-disabled": "Anonymous users cannot start meetings.",
    "spo-default-link-view": "Default sharing links grant view-only permission.",
    "teams-external-control-disabled": (
        "External participants cannot request control of shared content."
    ),
}


def test_belief_prose_distinct_for_compliant_findings(tmp_path: Path) -> None:
    """Compliant (ok) findings for the four formerly-colliding checks stay distinct.

    Each finding carries the evaluator's real ok summary as its Observed text;
    the Expected slot must bind the catalog expected_state and must never
    collapse to the same sentence.
    """
    result = empty_report()
    result.findings = [
        Finding(
            check_id=check_id,
            title=f"Compliant control {check_id}",
            workload=Workload.IDENTITY,
            status=FindingStatus.OK,
            severity=Severity.HIGH,
            value_impact=ValueImpact.HIGH,
            summary=ok_summary,
            deep_link=None,
            customer_title=f"Compliant control {check_id}",
            customer_summary="Plain-English compliant state for a busy admin.",
            customer_next_step="Nothing to do here.",
            confidence_label="High confidence",
            data_sources=["microsoft.graph"],
            limitations=[],
        )
        for check_id, ok_summary in _OK_FINDING_SUMMARIES.items()
    ]
    rendered = _render(result, tmp_path)
    chunks = _article_chunks(rendered)
    assert len(chunks) == len(result.findings), (
        f"expected one article per finding, got {len(chunks)} chunks for "
        f"{len(result.findings)} findings"
    )
    for chunk, finding in zip(chunks, result.findings, strict=True):
        expected = _belief_slot_text(chunk, "Expected")
        observed = _belief_slot_text(chunk, "Observed")
        assert expected == expected_state_map()[finding.check_id], (
            f"Expected slot drifted from the catalog for {finding.check_id}: {expected!r}"
        )
        assert expected != observed, (
            f"Expected and Observed collapsed for compliant {finding.check_id}: {expected!r}"
        )


# ---------------------------------------------------------------------------
# 3. Posture is data-driven (never hardcoded)
# ---------------------------------------------------------------------------


def test_posture_percent_is_data_driven_not_hardcoded(tmp_path: Path) -> None:
    """The posture percent flows from the model, never a hardcoded literal.

    The comprehensive fixture renders its own ``realized_percent``; an unrelated
    literal percent does not appear (unless it happens to equal the model); and the
    empty fixture renders 0%.
    """
    result = comprehensive_report()
    html = _render(result, tmp_path)
    percent = result.capability_rollup.realized_percent
    assert f"{percent}% realized" in html, "posture figure is not bound to realized_percent"
    unrelated = 17
    if percent != unrelated:
        assert f"{unrelated}% realized" not in html, (
            f"posture literal {unrelated}% leaked when the model says {percent}%"
        )
    assert "0% realized" in _render(empty_report(), tmp_path), (
        "empty fixture must render 0% realized"
    )


# ---------------------------------------------------------------------------
# 4. Motion / reduced-motion contract (browser, offline bundle entry)
# ---------------------------------------------------------------------------


def _posture_report(percent: int) -> ScanResult:
    """A minimal, browser-safe scan with a specific realized percent and no findings."""
    return ScanResult(
        version="0.3.0",
        tenant_display_name="Posture Demo Tenant",
        scan_mode="dry_run",
        scanned_at="2026-01-15T09:30:00+00:00",
        capability_rollup=CapabilityRollup(you_own=3, fully_working=2, realized_percent=percent),
        packs_scanned=["identity"],
    )


@pytest.mark.browser
def test_reduced_motion_posture_is_instant_without_reveal(browser: Browser, tmp_path: Path) -> None:
    """Under ``prefers-reduced-motion: reduce`` the digits show the model percent
    immediately and the body never gains the ``revealed``/``constellation-settled``
    classes (the count-up animation and stagger are skipped)."""
    result = _posture_report(percent=67)
    bundle = build_report_bundle(result, tmp_path / "bundle")
    context = browser.new_context(reduced_motion="reduce")
    page: Page = context.new_page()
    page.goto(bundle.entry_path.as_uri())
    page.wait_for_load_state("load")
    assert page.locator(".posture-figure .posture-digits").inner_text() == str(
        result.capability_rollup.realized_percent
    )
    body_classes = page.evaluate("() => document.body.className")
    assert "revealed" not in body_classes, "body gained the reveal class under reduced motion"
    assert "constellation-settled" not in body_classes, (
        "body gained the constellation-settled class under reduced motion"
    )
    context.close()


@pytest.mark.browser
def test_default_motion_reveals_constellation(browser: Browser, tmp_path: Path) -> None:
    """Without reduced motion the body eventually gains the ``revealed`` class."""
    result = _posture_report(percent=67)
    bundle = build_report_bundle(result, tmp_path / "bundle")
    context = browser.new_context()
    page: Page = context.new_page()
    page.goto(bundle.entry_path.as_uri())
    page.wait_for_load_state("load")
    page.wait_for_function("() => document.body.classList.contains('revealed')")
    assert "revealed" in page.evaluate("() => document.body.className")
    context.close()


# ---------------------------------------------------------------------------
# 5. No hardcoded percent literal in the bundle JS
# ---------------------------------------------------------------------------


def test_app_js_binds_posture_not_hardcoded_percent() -> None:
    """``app.js`` reads ``realized_percent`` from the data asset and never carries a
    hardcoded ``% realized`` literal."""
    app_js = (templates_dir() / "report_app" / "v2" / "app.js").read_text(encoding="utf-8")
    assert "realized_percent" in app_js, "app.js does not bind the posture percent from data"
    assert "% realized" not in app_js, "app.js hardcodes a posture percent literal"


# ---------------------------------------------------------------------------
# 6. Enum -> human copy in the exec area (masthead, meta rows, posture)
# ---------------------------------------------------------------------------


def test_exec_area_renders_human_enum_copy(tmp_path: Path) -> None:
    """Exec surfaces render human copy and never the raw enum values.

    The masthead mode label, the finding meta row (Scope / Evaluation), the
    Value-impact slot, and the posture sentence all carry presentation copy.
    Raw enum values may only remain in the technical drill-down / data
    attributes; the labeled exec surfaces never print them.
    """
    result = comprehensive_report()
    result.findings[0] = result.findings[0].model_copy(
        update={
            "blast_radius": BlastRadius.ADMIN,
            "evaluation_mode": EvaluationMode.PROXY,
        }
    )
    html = _render(result, tmp_path)
    plain = _plain(html)

    # Masthead / opening mode copy (dry_run scan).
    assert "Demo scan (synthetic data)" in html
    assert "dry_run" not in html, "raw scan-mode enum leaked into the single-file report"

    # Finding meta row: evaluation + scope.
    assert "Evaluation: Read directly" in plain, "direct mode did not render its human copy"
    assert "Evaluation: Approximated — verify in portal" in plain, (
        "proxy mode did not render its human copy"
    )
    assert "Scope: Administrator scope" in plain, "admin blast radius did not render its human copy"
    assert "Scope: All users" in plain, "all_users blast radius did not render its human copy"
    assert "Evaluation: direct" not in plain, "raw direct enum leaked into the meta row"
    assert "Evaluation: proxy" not in plain, "raw proxy enum leaked into the meta row"
    assert "Scope: admin" not in plain, "raw admin enum leaked into the meta row"
    assert "Scope: all_users" not in plain, "raw all_users enum leaked into the meta row"

    # Value-impact slot capitalization.
    assert "Value impact: High" in plain
    assert "Value impact: high" not in plain, "raw lowercase impact value leaked"

    # Posture sentence: data-driven reword, no awkward fragment.
    assert "2 of 3 priority capabilities still need attention" in plain
    assert "still not fully working" not in plain, "awkward posture fragment still rendered"

    # The bundle entry masthead uses the same copy mapping.
    bundle = build_report_bundle(result, tmp_path / "bundle")
    entry_html = bundle.entry_path.read_text(encoding="utf-8")
    assert "Demo scan (synthetic data)" in entry_html
    assert "dry_run" not in entry_html, "raw scan-mode enum leaked into the bundle entry"


# ---------------------------------------------------------------------------
# 7. Provenance footer (todo 20)
# ---------------------------------------------------------------------------


def _footer_region(html_text: str) -> str:
    """Extract the first ``<footer>…</footer>`` region from rendered HTML."""
    start = html_text.index("<footer")
    return html_text[start : html_text.index("</footer>", start)]


def test_provenance_footer_renders_data_driven_and_keeps_print(tmp_path: Path) -> None:
    """The provenance footer renders the mode legend, methodology, sampling
    disclosure, identity, and generated timestamp — all sourced from the model.

    The legend derives from the modes actually present in the findings (never a
    fixed list), the methodology sentence covers exactly the evidence paths in
    play, the identity is the tenant display name, and the timestamp flows from
    the frozen fixture's ``scanned_at``. No raw enum token may appear anywhere
    in the footer region, and the print stylesheet keeps the footer.
    """
    result = comprehensive_report()
    result.findings[0] = result.findings[0].model_copy(
        update={"evaluation_mode": EvaluationMode.PROXY}
    )
    result.findings[1] = result.findings[1].model_copy(
        update={"evaluation_mode": EvaluationMode.MANUAL}
    )
    html = _render(result, tmp_path)
    footer = _footer_region(html)

    # Legend: only the modes present, in human copy.
    assert "Direct read" in footer
    assert "Approximated (proxy) — verify in portal" in footer
    assert "Manual review" in footer
    assert "Read directly" not in footer, "filter-button copy leaked into the legend"
    assert "unsupported" not in footer

    # Methodology: the evidence paths actually in play.
    assert "Graph and PowerShell read configuration directly" in footer
    assert "Secure Score approximates where direct evidence is unavailable" in footer
    assert "manual review covers settings no API exposes" in footer

    # Sampling disclosure.
    assert "No sampling or truncation recorded for this scan." in footer

    # Identity + generated timestamp, both straight from the model.
    assert html_lib.escape(result.tenant_display_name) in footer
    assert result.display_scanned_at in footer
    assert f'datetime="{result.scanned_at}"' in footer

    # The existing advisory line survives.
    assert "read-only advisory, review before acting" in footer

    # No raw enum anywhere in the footer region.
    for raw in ("dry_run", "direct_with_proxy_fallback", "not_licensed", "evaluation_mode"):
        assert raw not in footer, f"raw enum {raw!r} leaked into the footer"

    # Print keeps the footer: the single-file stylesheet no longer hides it.
    assert "footer { display: none" not in html, "print stylesheet hides the provenance footer"


def test_provenance_footer_demo_fallback_and_print_css(tmp_path: Path) -> None:
    """A nameless dry-run scan labels its footer identity ``demo (synthetic)``,
    and the bundle stylesheet also keeps the footer in print."""
    result = empty_report()
    html = _render(result, tmp_path)
    footer = _footer_region(html)
    assert "demo (synthetic)" in footer
    assert "Your tenant" not in footer

    bundle_css = (templates_dir() / "report_app" / "v2" / "app.css").read_text(encoding="utf-8")
    assert "footer { display: none" not in bundle_css, "bundle print stylesheet hides the footer"

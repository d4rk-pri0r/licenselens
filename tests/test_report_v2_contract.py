"""v2 report surface contract tests (todo 14).

Covers the NEW v2 surface not already locked elsewhere: ``test_report_viewmodel``
owns belief-block field binding + determinism, and ``test_report_render`` owns the
DOM/design signature. This file adds five contracts over the same frozen fixtures:

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
"""

from __future__ import annotations

from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page

from licenselens.models import CapabilityRollup, ScanResult
from licenselens.paths import templates_dir
from licenselens.report.bundle import build_report_bundle
from licenselens.report.html import write_html_report
from licenselens.report.viewmodel import build_constellation
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
    comprehensive finding carries a ``deep_link``; and the fixture's actual
    ``customer_next_step`` and ``summary`` strings (not hardcoded copy) appear in
    the rendered HTML for the first finding.
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


def test_admin_destination_absent_without_deep_link(tmp_path: Path) -> None:
    """A finding with no ``deep_link`` renders no "Admin destination" slot."""
    html = _render(sparse_optional_fields_report(), tmp_path)
    assert "Admin destination" not in html, (
        "admin-destination slot rendered for a finding with no deep_link"
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

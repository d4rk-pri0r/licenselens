"""Browser contracts for the report application shell (Todo 26).

The bundle entry renders its findings list client-side from the serialized
``window.LICENSELENS_REPORT_JSON`` data asset, so these tests drive the real
offline ``file://`` bundle through Playwright and lock the navigation, search,
compound-filter, and pagination behaviors — including the negative fixtures
(long labels, zero results, 1,000 findings, keyboard-only).
"""

from __future__ import annotations

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
from licenselens.schema_contracts import (
    AcceptedRiskAnnotation,
    EvaluationMode,
)
from tests.report_fixtures import empty_report

pytestmark = pytest.mark.browser

SCANNED_AT = "2026-01-15T09:30:00+00:00"

_SCROLL_METRICS_JS = (
    "() => ({ scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth })"
)


def _finding(
    check_id: str,
    status: str,
    severity: str,
    confidence: str,
    mode: str,
    workload: str,
    profiles: list[str],
    *,
    title: str | None = None,
    summary: str | None = None,
) -> Finding:
    risks = [
        AcceptedRiskAnnotation(
            id=f"waiver-{check_id}-{profile}",
            check_id=check_id,
            profile_id=profile,
            owner="SecOps",
            reason="Accepted for review.",
        )
        for profile in profiles
    ]
    evidence = {"profile_id": profiles[0]} if profiles and not risks else {}
    return Finding(
        check_id=check_id,
        title=title or f"{check_id} control",
        workload=Workload(workload),
        status=FindingStatus(status),
        severity=Severity(severity),
        value_impact=ValueImpact.HIGH,
        impact=ValueImpact.HIGH,
        effort=Effort.HOURS,
        blast_radius=BlastRadius.ALL_USERS,
        summary=summary or f"{check_id}: {status} observed.",
        customer_title=title or f"{check_id} control",
        customer_summary=summary or f"{check_id} customer summary.",
        customer_next_step=f"Fix {check_id}.",
        confidence=Confidence(confidence),
        confidence_label=f"{confidence} confidence",
        evaluation_mode=EvaluationMode(mode),
        data_sources=["microsoft.graph"],
        limitations=["First limitation"],
        accepted_risks=risks,
        evidence=evidence,
    )


def app_findings_report() -> ScanResult:
    findings = [
        _finding(
            "a-gap-high",
            "gap",
            "high",
            "high",
            "direct",
            "identity",
            ["secops"],
            title="Enforce MFA for privileged admins",
            summary="Alpha remediation for privileged access.",
        ),
        _finding("b-gap-med", "gap", "medium", "medium", "proxy", "identity", []),
        _finding("c-partial", "partial", "high", "low", "manual", "endpoint", ["secops"]),
        _finding("d-ok", "ok", "low", "high", "direct", "defender", []),
        _finding("e-notlic", "not_licensed", "info", "medium", "unsupported", "sentinel", ["core"]),
        _finding("f-skip", "skipped", "medium", "low", "proxy", "purview", []),
        _finding("g-error", "error", "high", "medium", "manual", "identity", ["core"]),
        _finding("h-gap2", "gap", "critical", "high", "direct", "endpoint", []),
        _finding("i-partial2", "partial", "medium", "medium", "direct", "defender", ["secops"]),
        _finding("j-ok2", "ok", "info", "low", "proxy", "identity", []),
        _finding("k-skip2", "skipped", "low", "high", "unsupported", "sentinel", []),
        _finding("l-notlic2", "not_licensed", "info", "medium", "manual", "purview", ["core"]),
    ]
    return ScanResult(
        version="0.3.0",
        tenant_display_name="Contoso Demo Tenant",
        scan_mode="dry_run",
        scanned_at=SCANNED_AT,
        findings=findings,
        packs_scanned=["identity", "endpoint"],
    )


def long_labels_report() -> ScanResult:
    token = "x" * 160
    findings = [
        _finding(
            f"long-{token[:40]}",
            "gap",
            "high",
            "high",
            "direct",
            "identity",
            [],
            title=f"Long title {token}",
            summary=f"Long summary {token}",
        )
        for _ in range(3)
    ]
    return ScanResult(
        version="0.3.0",
        tenant_display_name=f"Tenant {token}",
        scan_mode="dry_run",
        scanned_at=SCANNED_AT,
        findings=findings,
        packs_scanned=["identity"],
    )


def thousand_findings_report() -> ScanResult:
    findings = [
        _finding(
            f"bulk-{index:04d}",
            "gap" if index % 3 == 0 else ("ok" if index % 3 == 1 else "partial"),
            ["high", "medium", "low"][index % 3],
            ["high", "medium", "low"][index % 3],
            ["direct", "proxy", "manual"][index % 3],
            ["identity", "endpoint", "defender", "sentinel", "purview"][index % 5],
            [],
        )
        for index in range(1000)
    ]
    return ScanResult(
        version="0.3.0",
        tenant_display_name="Bulk Tenant",
        scan_mode="dry_run",
        scanned_at=SCANNED_AT,
        findings=findings,
        packs_scanned=["identity", "endpoint"],
    )


@pytest.fixture
def app_uri(tmp_path: Path):
    def _build(result: ScanResult) -> str:
        bundle = build_report_bundle(result, tmp_path / "bundle")
        return bundle.entry_path.as_uri()

    return _build


def _visible_count(page: Page) -> str:
    return page.locator("[data-visible-count]").inner_text()


def _total_count(page: Page) -> str:
    return page.locator("[data-total-count]").inner_text()


# ---------------------------------------------------------------------------
# Interaction matrix (happy path)
# ---------------------------------------------------------------------------


def test_initial_render_and_navigation(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    page.wait_for_load_state("load")
    assert page.locator(".finding").count() == 12
    assert _visible_count(page) == "12"
    assert _total_count(page) == "12"
    assert page.locator("[data-workload-nav] [data-nav]").count() == 6
    assert page.locator("[data-filter-bar] [data-filter-value]").count() == 24
    assert page.locator(".pagination").is_hidden() is False
    assert page.locator("[data-empty-state]").is_hidden() is True


def test_status_or_within_group(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    page.locator('[data-filter-group="status"] [data-filter-value="gap"]').click()
    assert _visible_count(page) == "3"
    page.locator('[data-filter-group="status"] [data-filter-value="partial"]').click()
    assert _visible_count(page) == "5"
    gap = page.locator('[data-filter-group="status"] [data-filter-value="gap"]')
    partial = page.locator('[data-filter-group="status"] [data-filter-value="partial"]')
    assert gap.get_attribute("aria-pressed") == "true"
    assert partial.get_attribute("aria-pressed") == "true"


def test_and_across_groups(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    page.locator('[data-filter-group="status"] [data-filter-value="gap"]').click()
    assert _visible_count(page) == "3"
    page.locator('[data-filter-group="severity"] [data-filter-value="high"]').click()
    assert _visible_count(page) == "1"


def test_workload_navigation_syncs_filter(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    page.locator('[data-workload-nav] [data-nav="identity"]').click()
    assert _visible_count(page) == "4"
    identity_tab = page.locator('[data-workload-nav] [data-nav="identity"]')
    assert identity_tab.get_attribute("aria-current") == "page"
    chip = page.locator('[data-filter-group="workload"] [data-filter-value="identity"]')
    assert chip.get_attribute("aria-pressed") == "true"


def test_search_is_case_insensitive_and_safe(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    search = page.locator("#finding-search")
    search.fill("ALPHA")
    assert _visible_count(page) == "1"
    search.fill("alpha")
    assert _visible_count(page) == "1"
    search.fill("<script>alert(1)</script>")
    assert _visible_count(page) == "0"
    assert page.locator("script").count() == 2


def test_search_composes_with_filters(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    page.locator("#finding-search").fill("alpha")
    page.locator('[data-filter-group="status"] [data-filter-value="gap"]').click()
    assert _visible_count(page) == "1"
    page.locator('[data-filter-group="status"] [data-filter-value="gap"]').click()
    page.locator('[data-filter-group="status"] [data-filter-value="ok"]').click()
    assert _visible_count(page) == "0"


def test_mode_filter(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    assert page.locator('[data-filter-group="mode"] [data-filter-value="proxy"]').count() == 1
    page.locator('[data-filter-group="mode"] [data-filter-value="proxy"]').click()
    assert _visible_count(page) == "3"


def test_clear_all_resets_everything(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    page.locator("#finding-search").fill("alpha")
    page.locator('[data-filter-group="status"] [data-filter-value="gap"]').click()
    page.locator("[data-clear-filters]").click()
    assert _visible_count(page) == "12"
    assert page.locator("#finding-search").input_value() == ""
    assert page.locator(".filter-chip.is-active").count() == 0
    assert page.locator("[data-clear-filters]").is_disabled() is True


def test_empty_result_state_is_clear(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    page.locator("#finding-search").fill("no-such-token-anywhere")
    assert _visible_count(page) == "0"
    assert page.locator("[data-empty-state]").is_visible() is True
    assert "No findings match" in page.locator("[data-empty-state]").inner_text()
    assert page.locator(".pagination").is_hidden() is True


def test_empty_report_state(app_uri: str, page: Page) -> None:
    page.goto(app_uri(empty_report()))
    assert page.locator(".finding").count() == 0
    assert page.locator("[data-empty-state]").is_visible() is True
    assert "No findings were produced" in page.locator("[data-empty-state]").inner_text()
    assert _visible_count(page) == "0"
    assert _total_count(page) == "0"
    assert page.locator(".pagination").is_hidden() is True


# ---------------------------------------------------------------------------
# Pagination (25/50/100)
# ---------------------------------------------------------------------------


def test_pagination_25_50_100(app_uri: str, page: Page) -> None:
    page.goto(app_uri(thousand_findings_report()))
    assert page.locator(".finding-row").count() == 25
    assert page.locator("[data-page-indicator]").inner_text() == "Page 1 of 40"
    assert page.locator('[data-pager="prev"]').is_disabled() is True
    assert page.locator('[data-pager="next"]').is_disabled() is False

    page.locator('[data-pager="next"]').click()
    assert page.locator("[data-page-indicator]").inner_text() == "Page 2 of 40"

    page.locator("[data-page-size]").select_option("100")
    assert page.locator("[data-page-indicator]").inner_text() == "Page 1 of 10"
    assert page.locator(".finding-row").count() == 100

    page.locator("[data-page-size]").select_option("50")
    assert page.locator("[data-page-indicator]").inner_text() == "Page 1 of 20"


def test_single_scroll_owner_no_document_overflow(app_uri: str, page: Page) -> None:
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(app_uri(thousand_findings_report()))
    metrics = page.evaluate(
        "() => ({ docScroll: document.documentElement.scrollHeight,"
        " docClient: document.documentElement.clientHeight,"
        " docWidth: document.documentElement.scrollWidth,"
        " winWidth: window.innerWidth })"
    )
    assert metrics["docWidth"] <= metrics["winWidth"], "horizontal document overflow"
    # v2 scrolls the document itself (no inner fixed-height scroll container).
    assert metrics["docScroll"] > metrics["docClient"], "document should scroll with many findings"


def test_responsive_375_no_overflow(app_uri: str, page: Page) -> None:
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(app_uri(app_findings_report()))
    metrics = page.evaluate(_SCROLL_METRICS_JS)
    assert metrics["scrollWidth"] <= metrics["innerWidth"]


def test_long_labels_no_overflow(app_uri: str, page: Page) -> None:
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(app_uri(long_labels_report()))
    metrics = page.evaluate(_SCROLL_METRICS_JS)
    assert metrics["scrollWidth"] <= metrics["innerWidth"]
    assert page.locator(".finding-row").count() == 3


# ---------------------------------------------------------------------------
# Keyboard, focus, reduced motion, hash links, no persisted data
# ---------------------------------------------------------------------------


def test_keyboard_only_filter_flow(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    gap = page.locator('[data-filter-group="status"] [data-filter-value="gap"]')
    gap.focus()
    page.keyboard.press("Enter")
    assert gap.get_attribute("aria-pressed") == "true"
    assert _visible_count(page) == "3"
    page.keyboard.press("Space")
    assert gap.get_attribute("aria-pressed") == "false"
    assert _visible_count(page) == "12"
    assert gap.evaluate("el => el.matches(':focus')") is True


def test_focus_outline_on_chips(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    chip = page.locator('[data-filter-group="status"] [data-filter-value="gap"]')
    chip.focus()
    outline = chip.evaluate(
        "el => { const s = getComputedStyle(el);"
        " return { style: s.outlineStyle, width: s.outlineWidth }; }"
    )
    assert outline["style"] == "solid"
    assert float(outline["width"].removesuffix("px")) >= 2.0


def test_reduced_motion_no_transitions(app_uri: str, page: Page) -> None:
    page.emulate_media(reduced_motion="reduce")
    page.goto(app_uri(app_findings_report()))
    offenders = []
    for element in page.locator("button, a, summary, input").all():
        duration = element.evaluate("el => getComputedStyle(el).transitionDuration")
        if any(part.strip() != "0s" for part in duration.split(",")):
            offenders.append(element.evaluate("el => el.tagName"))
    assert not offenders, f"transitions not disabled under reduced motion: {offenders}"


def test_hash_deep_link_scrolls_to_finding(app_uri: str, page: Page) -> None:
    page.goto(app_uri(thousand_findings_report()) + "#finding-bulk-0100")
    page.wait_for_load_state("load")
    in_view = page.evaluate(
        "() => { const el = document.getElementById('finding-bulk-0100');"
        " if (!el) return false;"
        " const main = document.querySelector('main.app-main');"
        " const r = el.getBoundingClientRect();"
        " const m = main.getBoundingClientRect();"
        " return r.top >= m.top - 1 && r.bottom <= m.bottom + 1; }"
    )
    assert in_view is True


def test_no_persisted_tenant_data(app_uri: str, page: Page) -> None:
    page.goto(app_uri(app_findings_report()))
    page.locator("#finding-search").fill("alpha")
    page.locator('[data-filter-group="status"] [data-filter-value="gap"]').click()
    storage = page.evaluate("() => [window.localStorage.length, window.sessionStorage.length]")
    assert storage == [0, 0]

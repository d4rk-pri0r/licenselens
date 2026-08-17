"""Browser contracts for charts, drilldowns, evidence, exports, and print (Todo 27).

The report app renders everything client-side from ``window.LICENSELENS_REPORT_JSON``,
so these tests drive the real offline ``file://`` bundle and lock:

* local inline-SVG charts with names, descriptions, and equivalent tables/text;
* accessible evidence drawers (provenance, collection health, limitations,
  entitlement explanation, waiver state, remediation) that cannot inject markup;
* filtered JSON/CSV exports (client-side Blob downloads) with spreadsheet-formula
  escaping; and a print view that contains the complete unpaginated finding set.

Negatives cover a CSV formula payload, malicious evidence, a no-chart-data report,
and a 1,000-finding export.
"""

from __future__ import annotations

import json
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
    SourceReference,
)
from tests.report_fixtures import empty_report

pytestmark = pytest.mark.browser

SCANNED_AT = "2026-01-15T09:30:00+00:00"

MALICIOUS = "<script>alert(1)</script>"

CHART_KEYS = ["status", "workload", "confidence", "evaluation_mode"]

EVIDENCE_SECTIONS = [
    "Technical evidence",
    "Confidence",
    "Data sources",
    "Limitations",
    "Technical ID",
]


def _finding(
    check_id: str,
    *,
    status: str = "gap",
    severity: str = "high",
    confidence: str = "high",
    mode: str = "direct",
    workload: str = "identity",
    title: str | None = None,
    summary: str | None = None,
    evidence: dict | None = None,
    entitlements: list[str] | None = None,
    remediation: str | None = None,
    limitations: list[str] | None = None,
    data_sources: list[str] | None = None,
    source_refs: list[SourceReference] | None = None,
    accepted_risks: list[AcceptedRiskAnnotation] | None = None,
    next_step: str | None = None,
) -> Finding:
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
        customer_next_step=next_step or f"Fix {check_id}.",
        confidence=Confidence(confidence),
        confidence_label=f"{confidence} confidence",
        evaluation_mode=EvaluationMode(mode),
        data_sources=data_sources or ["microsoft.graph"],
        limitations=limitations or ["First limitation"],
        entitlements_used=entitlements or [],
        remediation=remediation or "",
        source_references=source_refs or [],
        accepted_risks=accepted_risks or [],
        evidence=evidence or {},
    )


def viz_report() -> ScanResult:
    findings = [
        _finding(
            "a-gap",
            status="gap",
            severity="high",
            confidence="high",
            mode="direct",
            workload="identity",
            evidence={"profile_id": "secops", "conditional_access_policies": 0},
            entitlements=["Microsoft 365 E5", "Azure AD Premium P2"],
            remediation="Create a Conditional Access policy that requires MFA.",
            limitations=["Policy count excludes deleted policies."],
            data_sources=["microsoft.graph"],
            source_refs=[
                SourceReference(
                    id="src-1",
                    kind="graph",
                    name="Conditional Access policies",
                    reference="GET /identity/conditionalAccess/policies",
                    collected_at="2026-01-15T09:29:00Z",
                )
            ],
            accepted_risks=[
                AcceptedRiskAnnotation(
                    id="waiver-a",
                    check_id="a-gap",
                    profile_id="secops",
                    owner="SecOps",
                    reason="Accepted for 30 days while rollouts complete.",
                )
            ],
        ),
        _finding(
            "b-gap",
            status="gap",
            severity="medium",
            confidence="medium",
            mode="proxy",
            workload="identity",
        ),
        _finding(
            "c-partial",
            status="partial",
            severity="high",
            confidence="low",
            mode="manual",
            workload="endpoint",
        ),
        _finding(
            "d-ok",
            status="ok",
            severity="low",
            confidence="high",
            mode="direct",
            workload="defender",
        ),
        _finding(
            "e-notlic",
            status="not_licensed",
            severity="info",
            confidence="medium",
            mode="unsupported",
            workload="sentinel",
        ),
        _finding(
            "f-error",
            status="error",
            severity="high",
            confidence="low",
            mode="manual",
            workload="identity",
        ),
    ]
    return ScanResult(
        version="0.3.0",
        tenant_display_name="Contoso Demo Tenant",
        scan_mode="dry_run",
        scanned_at=SCANNED_AT,
        findings=findings,
        packs_scanned=["identity", "endpoint"],
    )


def malicious_report() -> ScanResult:
    finding = _finding(
        "m-evil",
        status="gap",
        evidence={"note": MALICIOUS, "policies": [MALICIOUS, "<img src=x onerror=alert(1)>"]},
        summary=f"Injected {MALICIOUS} in the summary field.",
        entitlements=[MALICIOUS],
        remediation=f"Remediation with {MALICIOUS}.",
        limitations=[MALICIOUS],
        title=f"Title {MALICIOUS}",
    )
    return ScanResult(
        version="0.3.0",
        tenant_display_name="Malicious Tenant",
        scan_mode="dry_run",
        scanned_at=SCANNED_AT,
        findings=[finding],
        packs_scanned=["identity"],
    )


def formula_report() -> ScanResult:
    findings = [
        _finding("f-eq", title="=SUM(A1:A9)"),
        _finding("f-plus", title="+1+2"),
        _finding("f-minus", title="-2+3"),
        _finding("f-at", title="@import"),
        _finding("f-safe", title="Enforce MFA for admins"),
    ]
    return ScanResult(
        version="0.3.0",
        tenant_display_name="Formula Tenant",
        scan_mode="dry_run",
        scanned_at=SCANNED_AT,
        findings=findings,
        packs_scanned=["identity"],
    )


@pytest.fixture
def app_uri(tmp_path: Path):
    def _build(result: ScanResult) -> str:
        bundle = build_report_bundle(result, tmp_path / "bundle")
        return bundle.entry_path.as_uri()

    return _build


def _download(page: Page, selector: str) -> tuple[str, str]:
    with page.expect_download() as download_info:
        page.locator(selector).click()
    download = download_info.value
    path = download.path()
    assert path is not None, "download did not produce a file"
    return download.suggested_filename, path.read_text(encoding="utf-8")


def _chart_table_counts(page: Page, key: str) -> dict[str, int]:
    fig = page.locator(f'[data-chart="{key}"]')
    counts: dict[str, int] = {}
    for row in fig.locator("[data-chart-table] tbody tr").all():
        cells = row.locator("td").all()
        counts[cells[0].text_content().strip()] = int(cells[1].text_content().strip())
    return counts


# ---------------------------------------------------------------------------
# Charts: names, descriptions, local SVG, and nonvisual equivalents
# ---------------------------------------------------------------------------


def test_charts_render_names_descriptions_and_equivalents(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    for key in CHART_KEYS:
        fig = page.locator(f'[data-chart="{key}"]')
        assert fig.count() == 1, f"missing {key} chart"

        caption = fig.locator("figcaption").first.text_content().strip()
        assert caption, f"{key} chart missing a name"

        body = fig.locator('[role="img"]')
        assert body.count() == 1, f"{key} chart missing role=img"
        labelled_by = body.get_attribute("aria-labelledby")
        described_by = body.get_attribute("aria-describedby")
        assert labelled_by, f"{key} chart missing aria-labelledby"
        assert described_by, f"{key} chart missing aria-describedby"

        if key == "workload":
            assert fig.locator(".chart-rows").count() == 1, f"{key} chart missing icon rows"
            assert fig.locator(".chart-row").count() >= 1, f"{key} chart missing row entries"
        else:
            assert fig.locator("svg.chart-svg").count() == 1, f"{key} chart missing inline SVG"

        description = fig.locator(f"#{described_by}").text_content().strip()
        assert description, f"{key} chart missing its description"

        assert fig.locator("[data-chart-table]").count() == 1, f"{key} chart missing its table"


def test_status_chart_counts_match_findings(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    counts = _chart_table_counts(page, "status")
    assert counts == {
        "Action required": 2,
        "Incomplete": 1,
        "Operational": 1,
        "Not licensed": 1,
        "Not assessed": 0,
        "Verification failed": 1,
    }


def test_confidence_and_mode_chart_counts(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    assert _chart_table_counts(page, "confidence") == {"High": 2, "Medium": 2, "Low": 2}
    mode = _chart_table_counts(page, "evaluation_mode")
    assert mode == {
        "Read directly": 2,
        "Approximated — verify in portal": 1,
        "Manual review": 2,
        "Read directly (with fallback)": 0,
        "Unsupported": 1,
    }


def test_chart_equivalents_are_nonvisual(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    table = page.locator('[data-chart="status"] [data-chart-table]')
    props = table.evaluate(
        "el => ({ display: getComputedStyle(el).display,"
        " visibility: getComputedStyle(el).visibility,"
        " position: getComputedStyle(el).position })"
    )
    assert props["display"] != "none"
    assert props["visibility"] != "hidden"
    assert props["position"] == "absolute"


# ---------------------------------------------------------------------------
# Evidence drawer: accessible sections, markup-injection-proof
# ---------------------------------------------------------------------------


def test_evidence_drawer_has_all_sections(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    details = page.locator(".finding-row").first.locator("details.tech")
    text_content = details.text_content()
    for section in EVIDENCE_SECTIONS:
        assert section in text_content, f"evidence disclosure missing {section!r}"


def test_evidence_drawer_surfaces_data_sources_and_limitations(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    details = page.locator(".finding-row").first.locator("details.tech")
    text_content = details.text_content()
    assert "microsoft.graph" in text_content
    assert "Policy count excludes deleted policies." in text_content
    assert "high confidence" in text_content


def test_evidence_cannot_inject_markup(app_uri: str, page: Page) -> None:
    page.goto(app_uri(malicious_report()))
    assert page.locator("script").count() == 2, "injected <script> reached the DOM"
    assert page.locator(".finding-row img").count() == 0, "injected <img> reached finding DOM"
    assert page.locator(".finding-row script").count() == 0
    assert page.locator(".finding-row details.tech img").count() == 0

    finding = page.locator(".finding-row").first
    text_content = finding.text_content()
    assert MALICIOUS in text_content, "evidence content missing from the finding"
    assert "<img" not in finding.evaluate("el => el.innerHTML")


# ---------------------------------------------------------------------------
# Export: matches filters, escapes formulas, client-side only
# ---------------------------------------------------------------------------


def test_export_matches_active_filters(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    page.locator('[data-filter-group="status"] [data-filter-value="gap"]').click()

    _, csv_content = _download(page, '[data-export="csv"]')
    _, json_content = _download(page, '[data-export="json"]')
    exported = json.loads(json_content)

    assert len(exported) == 2
    assert {f["check_id"] for f in exported} == {"a-gap", "b-gap"}
    assert all(f["status"] == "gap" for f in exported)
    assert "a-gap" in csv_content and "b-gap" in csv_content
    assert "c-partial" not in csv_content


def test_json_export_is_complete_finding_data(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    _, json_content = _download(page, '[data-export="json"]')
    exported = json.loads(json_content)
    assert len(exported) == 6
    first = next(f for f in exported if f["check_id"] == "a-gap")
    assert first["evidence"]["conditional_access_policies"] == 0
    assert first["entitlements_used"] == ["Microsoft 365 E5", "Azure AD Premium P2"]


def test_csv_escapes_spreadsheet_formulas(app_uri: str, page: Page) -> None:
    page.goto(app_uri(formula_report()))
    filename, csv_content = _download(page, '[data-export="csv"]')
    assert filename == "licenselens-findings.csv"
    assert "'=SUM(A1:A9)" in csv_content
    assert "'+1+2" in csv_content
    assert "'-2+3" in csv_content
    assert "'@import" in csv_content
    assert "Enforce MFA for admins" in csv_content


def test_csv_header_row_present(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    _, csv_content = _download(page, '[data-export="csv"]')
    header = csv_content.splitlines()[0]
    assert header.startswith("Check ID,Title,Status,Severity,Confidence,Evaluation mode")
    assert header.endswith("Admin page")


# ---------------------------------------------------------------------------
# Print: complete unpaginated findings
# ---------------------------------------------------------------------------


def test_print_list_contains_complete_unpaginated_findings(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    assert page.locator(".finding-row").count() == 6
    assert page.locator("[data-print-list] .print-finding").count() == 6
    assert page.locator("[data-print-list] .finding-row").count() == 0
    display = page.locator("[data-print-list]").evaluate("el => getComputedStyle(el).display")
    assert display == "none"


def test_print_list_tracks_filters(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    page.locator('[data-filter-group="status"] [data-filter-value="gap"]').click()
    assert page.locator("[data-print-list] .print-finding").count() == 2


def test_print_button_exists_and_is_a_button(app_uri: str, page: Page) -> None:
    page.goto(app_uri(viz_report()))
    btn = page.locator("[data-print]")
    assert btn.count() == 1
    assert btn.get_attribute("type") == "button"


# ---------------------------------------------------------------------------
# Negatives: no-chart data and large export
# ---------------------------------------------------------------------------


def test_no_chart_data_message(app_uri: str, page: Page) -> None:
    page.goto(app_uri(empty_report()))
    assert page.locator("[data-chart-empty]").count() == 1
    assert page.locator("[data-chart]").count() == 0
    assert "No findings to chart" in page.locator("[data-chart-empty]").text_content()


def test_large_export(app_uri: str, page: Page, tmp_path: Path) -> None:
    from tests.test_report_app import thousand_findings_report

    page.goto(app_uri(thousand_findings_report()))
    _, json_content = _download(page, '[data-export="json"]')
    exported = json.loads(json_content)
    assert len(exported) == 1000

    _, csv_content = _download(page, '[data-export="csv"]')
    lines = csv_content.strip().splitlines()
    assert len(lines) == 1001
    assert lines[0].startswith("Check ID,")

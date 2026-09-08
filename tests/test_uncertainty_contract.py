"""TV-2 uncertainty contract: unknown entitlement, incomplete assessment, and
detection-matrix claims never masquerade as known-bad or known-good.

Covers the four evaluation failure modes end to end through
``capability_rollup`` + ``build_detection_realization`` + the rendered HTML
(hero and detection-realization sections):

1. Unknown entitlements are never ``not_licensed`` and never enter ``you_own``.
2. Missing ingestion evidence renders "Not assessed", never "No".
3. Ingestion OK + parity ERROR → watched is unknown, never inferred as 1.
4. Ingestion OK + parity GAP naming the table unwatched → watched_by == 0.
5. Ingestion OK + parity OK → a bounded watched_by=1 with an explicit basis.
6. Error-only capabilities are ``assessment_incomplete`` (outside the %);
   observed PARTIAL stays ``partly_set_up`` (inside the %).
7. The hero leads with the fraction, drops "Fully working", and the
   distribution bar draws only owned, evaluated capabilities.
8. The demo dry-run hero stays coherent under the new denominators.
"""

from __future__ import annotations

import re

from licenselens.auth import AuthContext, AuthMode
from licenselens.engine.loader import load_checks
from licenselens.engine.rollup import capability_rollup
from licenselens.engine.runner import run_scan
from licenselens.engine.runner_evaluate import evaluate_check
from licenselens.models import (
    CheckDefinition,
    CheckPack,
    Finding,
    FindingStatus,
    ScanResult,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.report.html import write_html_report
from licenselens.report.viewmodel import build_detection_realization

UNKNOWN_CAPS = frozenset(
    {
        "microsoft_sentinel",
        "log_analytics",
        "defender_for_cloud_cspm",
        "defender_for_cloud_servers",
    }
)


def _check(check_id: str, caps: list[str], pack: CheckPack) -> CheckDefinition:
    return CheckDefinition(
        id=check_id,
        title=check_id,
        workload=Workload.AZURE,
        required_capabilities=caps,
        pack=pack,
        impact=ValueImpact.MEDIUM,
    )


def _finding(
    check_id: str,
    status: FindingStatus,
    *,
    pack: CheckPack = CheckPack.IDENTITY,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        workload=Workload.SENTINEL,
        status=status,
        severity=Severity.MEDIUM,
        value_impact=ValueImpact.MEDIUM,
        impact=ValueImpact.MEDIUM,
        pack=pack,
        summary=f"{check_id}: {status.value}",
        evidence=evidence or {},
    )


def _ingestion_ok_finding() -> Finding:
    return _finding(
        "sen-telemetry-ingestion-coverage",
        FindingStatus.OK,
        evidence={
            "capabilities": {
                "conditional_access": {
                    "core_seen": ["SigninLogs"],
                    "extended_seen": [],
                    "missing_core": [],
                }
            },
            "mode": "query",
        },
    )


def _signin_row(result: ScanResult) -> dict:
    rows = build_detection_realization(result)["rows"]
    return next(row for row in rows if row["table"] == "SigninLogs")


def test_case1_unknown_entitlements_are_not_licensed_gaps():
    """Four unknown Azure caps, ten error findings, owned=[] → unknown==4."""
    checks = load_checks()
    targeted = [c for c in checks if set(c.required_capabilities) & UNKNOWN_CAPS]
    findings = [evaluate_check(c, set(), {}, entitlement_unknown=UNKNOWN_CAPS) for c in targeted]
    assert len(findings) == 10
    assert all(f.status is FindingStatus.ERROR for f in findings)
    packs = list({c.pack for c in targeted})
    rollup, outcomes = capability_rollup(
        targeted, findings, [], [], packs, entitlement_unknown=UNKNOWN_CAPS
    )
    assert rollup.entitlement_unknown == 4
    assert rollup.not_licensed == 0
    assert rollup.you_own == 0
    assert rollup.fully_working == 0
    assert rollup.realized_percent == 0
    assert rollup.realized_sentence == "No in-scope capabilities could be evaluated."
    assert outcomes == []


def test_case2_missing_ingestion_renders_not_assessed(tmp_path):
    """No ingestion finding → every row ingesting is None; template says so."""
    result = ScanResult(
        version="t",
        scanned_at="2026-09-08T00:00:00+00:00",
        owned_capabilities=["conditional_access"],
    )
    matrix = build_detection_realization(result)
    assert matrix["rows"]
    assert all(row["ingesting"] is None for row in matrix["rows"])
    assert all(row["watched_by"] is None for row in matrix["rows"])
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")
    detection = html[html.index("Detection realization") :]
    assert "Not assessed" in detection
    assert "Live rules (when assessed)" in detection


def test_case3_ingestion_ok_parity_error_watched_unknown():
    """Positive ingestion + parity ERROR → ingesting True, watched_by None."""
    result = ScanResult(
        version="t",
        scanned_at="2026-09-08T00:00:00+00:00",
        owned_capabilities=["conditional_access"],
        findings=[
            _ingestion_ok_finding(),
            _finding("sen-rule-telemetry-parity", FindingStatus.ERROR),
        ],
    )
    row = _signin_row(result)
    assert row["ingesting"] is True
    assert row["watched_by"] is None


def test_case4_parity_gap_names_table_unwatched():
    """Ingestion OK + parity GAP with SigninLogs unwatched → watched_by == 0."""
    result = ScanResult(
        version="t",
        scanned_at="2026-09-08T00:00:00+00:00",
        owned_capabilities=["conditional_access"],
        findings=[
            _ingestion_ok_finding(),
            _finding(
                "sen-rule-telemetry-parity",
                FindingStatus.GAP,
                evidence={"unwatched_tables": ["SigninLogs"], "dead_rules": []},
            ),
        ],
    )
    row = _signin_row(result)
    assert row["ingesting"] is True
    assert row["watched_by"] == 0
    assert row["watched_by_basis"] is None


def test_case5_parity_ok_yields_bounded_watch_marker():
    """Ingestion OK + parity OK → watched_by=1 with parity-not-unwatched basis."""
    result = ScanResult(
        version="t",
        scanned_at="2026-09-08T00:00:00+00:00",
        owned_capabilities=["conditional_access"],
        findings=[
            _ingestion_ok_finding(),
            _finding("sen-rule-telemetry-parity", FindingStatus.OK),
        ],
    )
    row = _signin_row(result)
    assert isinstance(row["watched_by"], int)
    assert row["watched_by"] >= 1
    assert row["watched_by"] == 1
    assert row["watched_by_basis"] == "parity-not-unwatched"


def test_case6_error_vs_partial_capability_statuses():
    """Error-only → assessment_incomplete; PARTIAL-only → partly_set_up."""
    error_checks = [_check("az-a", ["defender_for_cloud_cspm"], CheckPack.STARTER)]
    error_findings = [_finding("az-a", FindingStatus.ERROR, pack=CheckPack.STARTER)]
    rollup, outcomes = capability_rollup(
        error_checks, error_findings, ["defender_for_cloud_cspm"], [], ["starter"]
    )
    assert rollup.assessment_incomplete == 1
    assert rollup.partly_set_up == 0
    assert rollup.you_own == 0
    assert outcomes[0].status == "assessment_incomplete"

    partial_checks = [_check("id-a", ["conditional_access"], CheckPack.IDENTITY)]
    partial_findings = [_finding("id-a", FindingStatus.PARTIAL)]
    rollup2, outcomes2 = capability_rollup(
        partial_checks, partial_findings, ["conditional_access"], [], ["identity"]
    )
    assert rollup2.partly_set_up == 1
    assert rollup2.assessment_incomplete == 0
    assert rollup2.you_own == 1
    assert outcomes2[0].status == "partly_set_up"


def _uncertainty_report() -> ScanResult:
    from licenselens.models import CapabilityRollup, CapabilitySummary

    return ScanResult(
        version="t",
        scanned_at="2026-09-08T00:00:00+00:00",
        owned_capabilities=["conditional_access"],
        capability_summaries=[
            CapabilitySummary(
                id="conditional_access",
                name="Conditional Access",
                plain_name="Conditional Access",
            )
        ],
        findings=[
            _ingestion_ok_finding(),
            _finding("sen-rule-telemetry-parity", FindingStatus.ERROR),
        ],
        packs_scanned=["identity", "endpoint"],
        capability_rollup=CapabilityRollup(
            you_own=8,
            fully_working=3,
            needs_attention=3,
            partly_set_up=2,
            assessment_incomplete=1,
            not_licensed=3,
            entitlement_unknown=2,
            realized_percent=38,
        ),
    )


def test_case7_hero_html_honesty(tmp_path):
    """Fraction-first hero, no 'Fully working', owned-only bar, unknown named."""
    result = _uncertainty_report()
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")

    assert result.capability_rollup.realized_sentence in html
    assert "met all assessed criteria" in html
    assert "3 of 8 in-scope capabilities met all assessed criteria (38%)." in html
    assert "Fully working" not in html
    assert "Met assessed criteria" in html

    assert "dist-segment status-not_licensed" not in html
    dist_bar = re.search(
        r'<div class="dist-bar".*?</div>\s*<div class="dist-hits"',
        html,
        re.DOTALL,
    )
    assert dist_bar, "dist bar markup missing"
    bar_markup = dist_bar.group(0)
    assert "status-not_licensed" not in bar_markup
    assert "status-gap" in bar_markup
    if result.capability_rollup.assessment_incomplete:
        assert "status-skipped" in bar_markup

    assert "entitlement unknown" in html
    assert "not licensed" in html
    assert "Outside the bar" in html


def test_case8_demo_dry_run_hero_stays_coherent(tmp_path):
    """Demo dry-run keeps an internally consistent hero under the new rules."""
    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    rollup = result.capability_rollup
    assert rollup.you_own == (rollup.fully_working + rollup.needs_attention + rollup.partly_set_up)
    if rollup.you_own:
        assert rollup.realized_percent == round(rollup.fully_working / rollup.you_own * 100)
    else:
        assert rollup.realized_percent == 0
    assert re.fullmatch(
        r"(All \d+ in-scope capabilities met all assessed criteria \(100%\)."
        r"|\d+ of \d+ in-scope capabilities met all assessed criteria \(\d+%\)."
        r"|No in-scope capabilities could be evaluated\.)",
        rollup.realized_sentence,
    )
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")
    assert rollup.realized_sentence in html
    assert "Fully working" not in html
    assert "dist-segment status-not_licensed" not in html

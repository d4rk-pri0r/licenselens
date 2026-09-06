"""WS6-B: Maester JSON ingest mapped via SCuBA IDs with entitlement gating.

Fixture fields match ``Invoke-Maester -OutputJson``:
``Tests[].Name``, ``Result``, ``Tag``, ``ResultDetail.TestResult``.
A live sample could not be fetched this session (GitHub API blocked);
the fixture is synthetic and documents those fields.
"""

from __future__ import annotations

from pathlib import Path

from licenselens.catalog.coverage import scuba_policy_map
from licenselens.external.maester import (
    NOT_OWNED_FAILURE_VERDICT,
    OWNED_FAILURE_VERDICT,
    MaesterParseError,
    ingest_maester,
    parse_maester_results,
    render_maester_json,
    render_maester_markdown,
)
from licenselens.models import (
    Finding,
    FindingStatus,
    ScanResult,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.schema_contracts import EvaluationMode

FIXTURE = Path(__file__).parent / "fixtures" / "maester" / "sample-results.json"


def _finding(
    check_id: str,
    status: FindingStatus,
    *,
    entitlements: list[str] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        workload=Workload.IDENTITY,
        status=status,
        severity=Severity.HIGH,
        value_impact=ValueImpact.HIGH,
        summary=f"{check_id} {status.value}",
        entitlements_used=list(entitlements or []),
    )


def _scan(*findings: Finding, owned: list[str] | None = None) -> ScanResult:
    return ScanResult(
        version="0.4.0",
        scanned_at="2026-09-06T00:00:00+00:00",
        owned_capabilities=list(owned or []),
        findings=list(findings),
    )


def test_parse_sample_fixture() -> None:
    tests = parse_maester_results(FIXTURE)
    assert len(tests) == 3
    assert tests[0].name.startswith("MS.AAD.1.1v1")
    assert tests[0].failed
    assert "MS.AAD.1.1v1" in tests[0].scuba_ids
    assert tests[0].test_result
    assert tests[1].passed
    assert tests[2].scuba_ids == ()


def test_parse_rejects_malformed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    try:
        parse_maester_results(bad)
    except MaesterParseError:
        return
    raise AssertionError("expected MaesterParseError")


def test_tags_map_to_local_check_ids() -> None:
    tests = parse_maester_results(FIXTURE)
    mapping = scuba_policy_map()
    assert mapping["MS.AAD.1.1v1"] == ("id-ca-legacy-auth-block",)
    assert mapping["MS.AAD.2.1v1"] == ("id-ca-high-risk-users",)
    report = ingest_maester(tests, _scan(), policy_map=mapping)
    assert "MT.1001 - Custom Maester test without a SCuBA id" in report.unmapped
    assert any(row.check_id == "id-ca-legacy-auth-block" for row in report.mapped_failures)


def test_owned_failure_confirms_gap() -> None:
    tests = parse_maester_results(FIXTURE)
    scan = _scan(
        _finding(
            "id-ca-legacy-auth-block",
            FindingStatus.GAP,
            entitlements=["conditional_access"],
        ),
        owned=["conditional_access"],
    )
    report = ingest_maester(tests, scan)
    row = next(
        item for item in report.mapped_failures if item.check_id == "id-ca-legacy-auth-block"
    )
    assert row.entitlement == "owned"
    assert row.verdict == OWNED_FAILURE_VERDICT
    assert row.our_status == "gap"


def test_not_owned_failure_is_licensing_not_gap() -> None:
    tests = parse_maester_results(FIXTURE)
    scan = _scan(
        _finding("id-ca-legacy-auth-block", FindingStatus.NOT_LICENSED),
        owned=[],
    )
    report = ingest_maester(tests, scan)
    row = next(
        item for item in report.mapped_failures if item.check_id == "id-ca-legacy-auth-block"
    )
    assert row.entitlement == "not_licensed"
    assert row.verdict == NOT_OWNED_FAILURE_VERDICT


def test_disagreement_flagged() -> None:
    tests = parse_maester_results(FIXTURE)
    scan = _scan(
        _finding(
            "id-ca-legacy-auth-block",
            FindingStatus.OK,
            entitlements=["conditional_access"],
        ),
        _finding(
            "id-ca-high-risk-users",
            FindingStatus.GAP,
            entitlements=["identity_protection"],
        ),
        owned=["conditional_access", "identity_protection"],
    )
    report = ingest_maester(tests, scan)
    kinds = {row.kind for row in report.disagreements}
    assert "maester_fail_ours_ok" in kinds
    assert "ours_gap_maester_pass" in kinds
    assert scan.findings[0].evaluation_mode is not EvaluationMode.EXTERNAL


def test_renderers_are_deterministic() -> None:
    tests = parse_maester_results(FIXTURE)
    scan = _scan(
        _finding(
            "id-ca-legacy-auth-block",
            FindingStatus.GAP,
            entitlements=["conditional_access"],
        ),
        owned=["conditional_access"],
    )
    report = ingest_maester(tests, scan)
    assert render_maester_json(report) == render_maester_json(report)
    md = render_maester_markdown(report)
    assert md == render_maester_markdown(report)
    assert "You pay for the capability this test covers" in md
    assert "`external`" in md


def test_cli_ingest_maester(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from licenselens.cli import app

    scan = tmp_path / "scan.json"
    scan.write_text(
        _scan(
            _finding(
                "id-ca-legacy-auth-block",
                FindingStatus.GAP,
                entitlements=["conditional_access"],
            ),
            owned=["conditional_access"],
        ).model_dump_json(),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["ingest", "maester", str(FIXTURE), "--scan", str(scan), "-o", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert (out / "security-license-lens-external-maester.json").is_file()
    assert (out / "security-license-lens-external-maester.md").is_file()


def test_cli_ingest_parse_error(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from licenselens.cli import app

    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    scan = tmp_path / "scan.json"
    scan.write_text(_scan().model_dump_json(), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["ingest", "maester", str(bad), "--scan", str(scan), "-o", str(tmp_path / "out")],
    )
    assert result.exit_code == 2

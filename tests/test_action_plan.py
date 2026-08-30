"""Tests for the G1 action-plan export (--export csv|json) and its redaction."""

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from licenselens.cli import app
from licenselens.config_models import RedactionSettings
from licenselens.models import (
    BlastRadius,
    CheckPack,
    Effort,
    ExposureClass,
    Finding,
    FindingStatus,
    ScanResult,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.report.action_plan import write_action_plan

runner = CliRunner()

#: A tenant id, a UPN-like string, and a tenant domain that must never survive
#: a redacted action-plan export.
_TENANT_ID = "11111111-2222-3333-4444-555555555555"
_UPN = "alice@contoso.com"
_DOMAIN = "contoso.com"


def _scan_result_with_sensitive_finding() -> ScanResult:
    """Build a ScanResult whose action-plan fields carry tenant data."""
    finding = Finding(
        check_id="id-ca-priv-gaps",
        title=f"Privileged sign-ins not gated for {_UPN}",
        workload=Workload.IDENTITY,
        status=FindingStatus.GAP,
        severity=Severity.HIGH,
        value_impact=ValueImpact.HIGH,
        effort=Effort.HOURS,
        blast_radius=BlastRadius.ALL_USERS,
        pack=CheckPack.IDENTITY,
        exposure_class=ExposureClass.ELEVATED,
        deep_link=f"https://entra.microsoft.com/tenant/{_TENANT_ID}/policies",
        summary="observed",
        remediation=f"Review {_UPN} in tenant {_TENANT_ID} on {_DOMAIN}.",
        customer_next_step=f"Enforce MFA for {_UPN} on {_DOMAIN}.",
    )
    return ScanResult(
        version="0.0.0-test",
        tenant_id=_TENANT_ID,
        tenant_display_name="Contoso",
        scanned_at="2026-01-01T00:00:00Z",
        findings=[finding],
    )


def test_demo_export_action_plan_csv_row_count_matches_json(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["demo", "--output-dir", str(out), "--export", "action-plan", "--no-redact"]
    )
    assert result.exit_code == 0, result.output
    csv_path = out / "action-plan.csv"
    assert csv_path.is_file()

    payload = json.loads((out / "security-license-lens-report.json").read_text(encoding="utf-8"))
    expected = sum(1 for f in payload["findings"] if f["status"] in {"gap", "partial"})
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == expected
    assert rows[0]["check_id"]
    assert rows[0]["title"]
    assert rows[0]["severity"]
    assert rows[0]["effort"]
    assert rows[0]["timeline"]
    assert rows[0]["reason"]
    assert rows[0]["customer_next_step"]
    assert rows[0]["deep_link"]


def test_demo_export_json_writes_action_plan_json(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["demo", "--output-dir", str(out), "--export", "json", "--no-redact"]
    )
    assert result.exit_code == 0, result.output
    json_path = out / "action-plan.json"
    assert json_path.is_file()
    rows = json.loads(json_path.read_text(encoding="utf-8"))
    assert isinstance(rows, list) and rows
    assert set(rows[0]) == {
        "check_id",
        "title",
        "capability",
        "entitlement",
        "severity",
        "risk",
        "effort",
        "timeline",
        "implementation_category",
        "reason",
        "current_evidence",
        "reference",
        "manual_validation_needed",
        "customer_next_step",
        "deep_link",
    }


def test_action_plan_csv_is_deterministic(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    for out in (first, second):
        result = runner.invoke(
            app, ["demo", "--output-dir", str(out), "--export", "action-plan", "--no-redact"]
        )
        assert result.exit_code == 0, result.output
    assert (first / "action-plan.csv").read_bytes() == (second / "action-plan.csv").read_bytes()


def test_action_plan_csv_escapes_commas_quotes_newlines(tmp_path: Path):
    finding = Finding(
        check_id="id-escaped",
        title='Title with "quotes", comma',
        workload=Workload.IDENTITY,
        status=FindingStatus.PARTIAL,
        severity=Severity.MEDIUM,
        value_impact=ValueImpact.MEDIUM,
        effort=Effort.DAYS,
        blast_radius=BlastRadius.ALL_USERS,
        pack=CheckPack.IDENTITY,
        exposure_class=ExposureClass.NONE,
        deep_link=None,
        summary="observed",
        remediation="Line one\nLine two, with comma",
        customer_next_step="Step, with comma",
    )
    result = ScanResult(
        version="0.0.0-test",
        tenant_id=None,
        scanned_at="2026-01-01T00:00:00Z",
        findings=[finding],
    )
    path = tmp_path / "action-plan.csv"
    write_action_plan(result, path, fmt="csv")
    text = path.read_text(encoding="utf-8")
    assert "\ufeff" not in text  # no BOM
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["title"] == 'Title with "quotes", comma'
    # On-disk CSV is LF-stable on every platform (Excel opens LF CSVs); a
    # \r\n here means the writer let text-mode newline translation leak in.
    assert b"\r\n" not in path.read_bytes()
    # Embedded newlines must survive as exactly one LF after normalization.
    reason = rows[0]["reason"].replace("\r\n", "\n")
    assert reason == "Line one\nLine two, with comma"
    assert rows[0]["customer_next_step"] == "Step, with comma"
    assert rows[0]["deep_link"] == ""


def test_action_plan_redaction_strips_tenant_id_upn_domain(tmp_path: Path):
    result = _scan_result_with_sensitive_finding()
    path = tmp_path / "action-plan.csv"
    write_action_plan(
        result,
        path,
        fmt="csv",
        redaction=RedactionSettings(enabled=True, redact_domains=True),
    )
    text = path.read_text(encoding="utf-8")
    assert _TENANT_ID not in text
    assert _UPN not in text
    assert _DOMAIN not in text
    assert "[redacted]" in text


def test_action_plan_no_redact_keeps_raw_values(tmp_path: Path):
    result = _scan_result_with_sensitive_finding()
    path = tmp_path / "action-plan.csv"
    write_action_plan(result, path, fmt="csv", redaction=None)
    text = path.read_text(encoding="utf-8")
    assert _TENANT_ID in text
    assert _UPN in text
    assert _DOMAIN in text


def test_zero_gap_scan_writes_empty_action_plan_with_header_row(tmp_path: Path):
    result = ScanResult(
        version="0.0.0-test",
        tenant_id=None,
        scanned_at="2026-01-01T00:00:00Z",
        findings=[
            Finding(
                check_id="id-ok-check",
                title="Everything is fine",
                workload=Workload.IDENTITY,
                status=FindingStatus.OK,
                severity=Severity.LOW,
                value_impact=ValueImpact.LOW,
                effort=Effort.MINUTES,
                blast_radius=BlastRadius.ALL_USERS,
                pack=CheckPack.IDENTITY,
                exposure_class=ExposureClass.NONE,
                deep_link=None,
                summary="observed",
            )
        ],
    )
    path = tmp_path / "action-plan.csv"
    write_action_plan(result, path, fmt="csv")
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == []
    text = path.read_text(encoding="utf-8")
    for column in (
        "check_id",
        "title",
        "severity",
        "effort",
        "timeline",
        "reason",
        "customer_next_step",
        "deep_link",
    ):
        assert column in text


def test_invalid_export_exits_2_and_writes_nothing(tmp_path: Path):
    out = tmp_path / "out"
    result = runner.invoke(app, ["demo", "--output-dir", str(out), "--export", "bogus"])
    assert result.exit_code == 2
    assert "bogus" in result.output
    assert "not one of" in result.output
    assert not out.exists()

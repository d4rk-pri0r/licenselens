"""WS6-A: activation vs hygiene tiers."""

from __future__ import annotations

from licenselens.auth import AuthContext, AuthMode
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import run_scan
from licenselens.models import CheckTier
from licenselens.report.html import write_html_report
from licenselens.report.markdown import write_markdown_report


def test_every_enabled_check_has_tier() -> None:
    missing = [check.id for check in load_checks() if check.enabled and check.tier is None]
    assert not missing
    unknown = [
        check.id
        for check in load_checks()
        if check.enabled and check.tier not in {CheckTier.ACTIVATION, CheckTier.HYGIENE}
    ]
    assert not unknown


def test_validate_check_tiers_script_is_clean() -> None:
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "scripts" / "validate_check_tiers.py"
    spec = importlib.util.spec_from_file_location("validate_check_tiers", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert module.validate_check_tiers() == []


def test_activation_scan_omits_hygiene_findings() -> None:
    result = run_scan(
        AuthContext(mode=AuthMode.DRY_RUN),
        dry_run=True,
        tiers=[CheckTier.ACTIVATION],
    )
    hygiene = [finding.check_id for finding in result.findings if finding.tier is CheckTier.HYGIENE]
    assert not hygiene
    assert result.tiers_scanned == ["activation"]
    assert any(finding.tier is CheckTier.ACTIVATION for finding in result.findings)


def test_activation_tier_never_spawns_bridge(monkeypatch) -> None:
    calls: list[str] = []

    def _boom(*_args, **_kwargs):
        calls.append("spawn")
        raise AssertionError("PowerShell bridge must not spawn on --tier activation")

    monkeypatch.setattr(
        "licenselens.collectors.powershell.invoke_powershell_adapter",
        _boom,
    )
    monkeypatch.setattr(
        "licenselens.collectors.exchange.collect_exchange_evidence",
        _boom,
    )
    monkeypatch.setattr(
        "licenselens.collectors.collaboration.collect_collaboration_evidence",
        _boom,
    )
    monkeypatch.setattr(
        "licenselens.collectors.power_data.collect_power_data_evidence",
        _boom,
    )
    result = run_scan(
        AuthContext(mode=AuthMode.DRY_RUN),
        dry_run=True,
        tiers=[CheckTier.ACTIVATION],
    )
    assert not calls
    assert result.tiers_scanned == ["activation"]


def test_report_splits_hygiene_section(tmp_path) -> None:
    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")
    md = write_markdown_report(result, tmp_path / "r.md").read_text(encoding="utf-8")
    assert "Activation assessment:" in html
    assert "Configuration hygiene (SCuBA-aligned, optional pack)" in html
    assert "Activation assessment:" in md
    assert "## Configuration hygiene (SCuBA-aligned, optional pack)" in md

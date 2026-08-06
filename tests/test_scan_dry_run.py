from pathlib import Path

from licenselens.auth import AuthMode, build_auth_context
from licenselens.engine.runner import run_scan
from licenselens.models import FindingStatus
from licenselens.report import write_html_report, write_json_report, write_markdown_report


def test_dry_run_scan_produces_findings(tmp_path: Path):
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    result = run_scan(auth, dry_run=True)

    assert result.owned_capabilities
    assert result.findings
    assert any(f.status == FindingStatus.SKIPPED for f in result.findings)

    html = write_html_report(result, tmp_path / "r.html")
    js = write_json_report(result, tmp_path / "r.json")
    md = write_markdown_report(result, tmp_path / "r.md")

    assert html.is_file() and "LicenseLens" in html.read_text(encoding="utf-8")
    assert js.is_file() and js.stat().st_size > 10
    assert md.is_file() and md.read_text(encoding="utf-8").startswith("# LicenseLens")

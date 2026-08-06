from pathlib import Path

from licenselens.auth import AuthMode, build_auth_context
from licenselens.engine.runner import run_scan
from licenselens.models import FindingStatus
from licenselens.report import write_html_report, write_json_report, write_markdown_report


def test_dry_run_scan_produces_findings(tmp_path: Path):
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    result = run_scan(auth, dry_run=True)

    assert result.owned_capabilities
    assert result.capability_summaries
    assert result.findings
    assert result.recommended_next_steps
    assert any(f.status == FindingStatus.SKIPPED for f in result.findings)
    assert all(f.customer_title for f in result.findings)
    assert any("admin" in c.plain_name.lower() for c in result.capability_summaries)

    html = write_html_report(result, tmp_path / "r.html")
    js = write_json_report(result, tmp_path / "r.json")
    md = write_markdown_report(result, tmp_path / "r.md")

    html_text = html.read_text(encoding="utf-8")
    md_text = md.read_text(encoding="utf-8")
    assert "LicenseLens" in html_text
    assert "What you already pay for" in html_text
    assert "plain English" in html_text.lower() or "What it does" in html_text
    assert "Recommended first steps" in html_text
    assert js.is_file() and "customer_title" in js.read_text(encoding="utf-8")
    assert md_text.startswith("# LicenseLens")
    assert "What you already pay for" in md_text
    assert "In plain English" in md_text

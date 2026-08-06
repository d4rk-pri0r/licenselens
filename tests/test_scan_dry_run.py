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
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["id-ca-priv-gaps"].status == FindingStatus.PARTIAL
    assert by_id["id-idprotect-off"].status == FindingStatus.GAP
    assert by_id["id-pim-unused"].status == FindingStatus.GAP
    assert by_id["id-dormant-privileged"].status in {
        FindingStatus.GAP,
        FindingStatus.PARTIAL,
    }
    assert by_id["mdo-p2-policies-default"].status in {
        FindingStatus.GAP,
        FindingStatus.PARTIAL,
    }
    assert by_id["mde-onboard-gap"].status == FindingStatus.GAP
    assert by_id["mdi-sensors-missing"].status in {
        FindingStatus.GAP,
        FindingStatus.PARTIAL,
        FindingStatus.OK,
    }
    # Sentinel / Purview still pending
    assert by_id["sen-analytics-rule-coverage"].status == FindingStatus.SKIPPED
    assert by_id["pur-dlp-not-enforced"].status == FindingStatus.SKIPPED
    assert all(f.customer_title for f in result.findings)
    assert result.has_actionable_gaps
    assert any("admin" in c.plain_name.lower() for c in result.capability_summaries)

    html = write_html_report(result, tmp_path / "r.html")
    js = write_json_report(result, tmp_path / "r.json")
    md = write_markdown_report(result, tmp_path / "r.md")

    html_text = html.read_text(encoding="utf-8")
    md_text = md.read_text(encoding="utf-8")
    assert "Security License Lens" in html_text
    assert "What you already pay for" in html_text
    assert "plain English" in html_text.lower() or "What it does" in html_text
    assert "Recommended first steps" in html_text
    assert js.is_file() and "customer_title" in js.read_text(encoding="utf-8")
    assert md_text.startswith("# Security License Lens")
    assert "What you already pay for" in md_text
    assert "In plain English" in md_text

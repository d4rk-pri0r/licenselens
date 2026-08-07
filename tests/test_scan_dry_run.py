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
    # Email pack off default path (no Graph API for MDO policy config).
    assert by_id["mdo-p2-policies-default"].status == FindingStatus.SKIPPED
    assert by_id["mdo-p2-policies-default"].evidence.get("email_proxy_enabled") is False
    assert by_id["mde-onboard-gap"].status == FindingStatus.GAP
    assert by_id["mdi-sensors-missing"].status in {
        FindingStatus.GAP,
        FindingStatus.PARTIAL,
        FindingStatus.OK,
    }
    assert by_id["sen-analytics-rule-coverage"].status == FindingStatus.PARTIAL
    assert by_id["sen-ueba-not-enabled"].status == FindingStatus.GAP
    assert by_id["pur-dlp-not-enforced"].status == FindingStatus.GAP
    # Default packs are identity + endpoint (email off by default).
    assert "email" not in result.packs_scanned
    assert "identity" in result.packs_scanned
    assert "endpoint" in result.packs_scanned
    assert all(m.check_ids[0] != "mdo-p2-policies-default" for m in result.moves)
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


def test_email_proxy_opt_in_uses_secure_score():
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    result = run_scan(
        auth,
        dry_run=True,
        allow_email_proxy=True,
        packs=["identity", "email", "endpoint"],
    )
    by_id = {f.check_id: f for f in result.findings}
    mdo = by_id["mdo-p2-policies-default"]
    assert mdo.status in {FindingStatus.GAP, FindingStatus.PARTIAL}
    assert mdo.evidence.get("proxy") is True
    assert "email" in result.packs_scanned


def test_html_top_card_shows_rollup_and_moves(tmp_path: Path):
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")

    # Hero top card renders the rollup numbers and sentence.
    assert "Your security at a glance" in html
    assert "Protections you own" in html
    assert "Fully working" in html
    assert "Realized" in html
    assert str(result.capability_rollup.you_own) in html
    assert result.capability_rollup.realized_sentence in html
    assert "Need attention" in html

    # Prioritized moves surface with owner-voice labels.
    assert "Top things to do first" in html
    for move in result.moves:
        assert move.title in html
        assert move.effort_label.lower() in html.lower()


def test_markdown_report_leads_with_executive_summary(tmp_path: Path):
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)
    md = write_markdown_report(result, tmp_path / "r.md").read_text(encoding="utf-8")

    # Executive summary precedes findings: rollup sentence, moves, exposed note.
    assert result.capability_rollup.realized_sentence in md
    assert "Protections you own:" in md
    assert "Top things to do first" in md
    assert result.moves[0].title in md
    assert md.index(result.capability_rollup.realized_sentence) < md.index("## Where you may")

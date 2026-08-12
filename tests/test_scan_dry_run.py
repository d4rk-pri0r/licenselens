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
    assert by_id["id-idprotect-off"].status == FindingStatus.OK
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
    # New identity depth checks
    assert by_id["id-security-defaults-on"].status == FindingStatus.GAP
    assert by_id["id-access-reviews-unused"].status == FindingStatus.GAP
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
    assert html_text.count("Top things to do first") == 1
    assert "Recommended first steps" not in html_text
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
    assert "Licensed capabilities detected" in html
    assert "Prioritized capabilities" in html
    assert "Fully working" in html
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

    assert result.capability_rollup.realized_sentence in md
    assert "Licensed capabilities detected:" in md
    assert "Prioritized capabilities:" in md
    assert "Top things to do first" in md
    assert result.moves[0].title in md
    assert md.index(result.capability_rollup.realized_sentence) < md.index("## Where you may")


def test_reports_distinguish_detected_from_prioritized_capabilities(tmp_path: Path):
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")
    md = write_markdown_report(result, tmp_path / "r.md").read_text(encoding="utf-8")

    detected = len(result.owned_capabilities)
    prioritized = result.capability_rollup.you_own
    assert detected > prioritized
    assert f"{result.capability_rollup.realized_percent}% realized" in html
    for report in (html, md):
        assert "Licensed capabilities detected" in report
        assert str(detected) in report
        assert "Prioritized capabilities" in report
        assert str(prioritized) in report
        assert "identity" in report
        assert "endpoint" in report
        assert f"of {prioritized} prioritized capabilities" in report
        for cap in result.capability_summaries:
            assert ", ".join(cap.matched_skus) in report
            if cap.matched_service_plans:
                assert ", ".join(cap.matched_service_plans) in report


def test_reports_identify_priority_packs(tmp_path: Path):
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")
    md = write_markdown_report(result, tmp_path / "r.md").read_text(encoding="utf-8")

    for report in (html, md):
        assert "priority packs" in report
        assert "packs scanned" not in report


def test_reports_surface_evidence_and_one_action_plan(tmp_path: Path):
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")
    md = write_markdown_report(result, tmp_path / "r.md").read_text(encoding="utf-8")

    finding_with_limitations = next(f for f in result.findings if f.limitations)
    exposed_findings = [f for f in result.findings if f.check_id in result.exposed_check_ids]
    for report in (html, md):
        assert report.count("Top things to do first") == 1
        assert "Recommended first steps" not in report
        if exposed_findings:
            assert "High-risk priority (fix first)" in report
            assert exposed_findings[0].display_customer_title in report
        assert finding_with_limitations.confidence_label in report
        assert ", ".join(finding_with_limitations.data_sources) in report
        assert finding_with_limitations.limitations[0].rstrip(".") in report
        assert finding_with_limitations.deep_link in report
        assert "Open Microsoft admin page" in report

from pathlib import Path

from licenselens.auth import AuthMode, build_auth_context
from licenselens.engine.runner import run_scan
from licenselens.friendly_names import friendly_plan_name, friendly_sku_name
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
    # Direct EXO fixture supersedes Secure Score; proxy stays opt-in fallback only.
    mdo = by_id["mdo-p2-policies-default"]
    assert mdo.status in {FindingStatus.OK, FindingStatus.PARTIAL, FindingStatus.GAP}
    assert mdo.evidence.get("proxy") is False
    assert mdo.evidence.get("exchange_direct") is True
    assert mdo.evidence.get("email_proxy_enabled") is False
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
    assert "What you're paying for" in html_text
    assert "What it does" in html_text or "Why it matters" in html_text
    # Section C heading appears twice: the section h2 and its table-of-contents
    # link under the masthead (DESIGN_V2 §6, same anchors, same labels).
    assert html_text.count("What matters most") == 2
    assert "Recommended first steps" not in html_text
    assert js.is_file() and "customer_title" in js.read_text(encoding="utf-8")
    assert md_text.startswith("# Security License Lens")
    assert "What you already pay for" in md_text
    assert "In plain English" in md_text


def test_dry_run_serializes_correct_evaluation_modes():
    from licenselens.schema_contracts import EvaluationMode

    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)
    by_id = {f.check_id: f for f in result.findings}

    assert by_id["mdi-sensors-missing"].evaluation_mode is EvaluationMode.PROXY
    assert by_id["pur-dlp-not-enforced"].evaluation_mode is EvaluationMode.PROXY
    assert by_id["id-logs-to-soc"].evaluation_mode is EvaluationMode.MANUAL
    assert by_id["id-idprotect-notify-high-risk"].evaluation_mode is EvaluationMode.MANUAL
    # MDO is evaluated directly in dry-run because the EXO fixture supersedes Secure Score.
    assert by_id["mdo-p2-policies-default"].evaluation_mode is EvaluationMode.DIRECT

    dumped = result.model_dump(mode="json")
    serialized = {f["check_id"]: f["evaluation_mode"] for f in dumped["findings"]}
    assert serialized["mdi-sensors-missing"] == "proxy"
    assert serialized["pur-dlp-not-enforced"] == "proxy"
    assert serialized["id-logs-to-soc"] == "manual"
    assert serialized["id-idprotect-notify-high-risk"] == "manual"


def test_email_proxy_opt_in_does_not_override_direct_exchange():
    """When direct EXO threat reads are usable, they supersede Secure Score proxy."""
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    result = run_scan(
        auth,
        dry_run=True,
        allow_email_proxy=True,
        packs=["identity", "email", "endpoint"],
    )
    by_id = {f.check_id: f for f in result.findings}
    mdo = by_id["mdo-p2-policies-default"]
    assert mdo.evidence.get("proxy") is False
    assert mdo.evidence.get("exchange_direct") is True
    assert "email" in result.packs_scanned


def test_email_proxy_used_only_when_direct_unusable():
    from licenselens.collectors.secure_score import DEMO_SECURE_SCORE, extract_control_scores
    from licenselens.engine.evaluate import evaluate_mdo_p2_policies
    from licenselens.models import CheckDefinition, Workload

    check = CheckDefinition(
        id="mdo-p2-policies-default",
        title="mdo",
        workload=Workload.DEFENDER,
    )
    result = evaluate_mdo_p2_policies(
        check,
        {
            "exchange_threat_usable": False,
            "secure_score_controls": extract_control_scores(DEMO_SECURE_SCORE),
        },
    )
    assert result.status in {FindingStatus.GAP, FindingStatus.PARTIAL}
    assert result.evidence.get("proxy") is True


def test_html_top_card_shows_rollup_and_moves(tmp_path: Path):
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    result = run_scan(auth, dry_run=True)
    html = write_html_report(result, tmp_path / "r.html").read_text(encoding="utf-8")

    # Hero opening renders the dominant posture figure, the supporting stat
    # strip, and the detected-vs-prioritized distinction.
    assert "Where you stand" in html
    assert "licensed capabilities detected" in html
    assert "prioritized capabilities" in html
    assert "Fully working" in html
    assert str(result.capability_rollup.you_own) in html
    assert result.capability_rollup.realized_sentence in html
    assert "Action required" in html

    # Prioritized moves surface with owner-voice labels.
    assert "What matters most" in html
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
        assert str(detected) in report
        assert str(prioritized) in report
        assert "identity" in report
        assert "endpoint" in report
        for cap in result.capability_summaries:
            assert ", ".join(friendly_sku_name(name) for name in cap.matched_skus) in report
            if cap.matched_service_plans:
                friendly = ", ".join(
                    friendly_plan_name(name) for name in cap.matched_service_plans
                )
                assert friendly in report
    assert "licensed capabilities detected" in html
    assert "prioritized capabilities" in html
    assert f"of {prioritized} prioritized" in html
    assert "Licensed capabilities detected" in md
    assert "Prioritized capabilities" in md
    assert f"of {prioritized} prioritized capabilities" in md


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
    # Section C heading + its table-of-contents link (DESIGN_V2 §6).
    assert html.count("What matters most") == 2
    assert md.count("Top things to do first") == 1
    for report in (html, md):
        assert "Recommended first steps" not in report
        if exposed_findings:
            assert "High-risk priority (fix first)" in report
            assert exposed_findings[0].display_customer_title in report
        assert finding_with_limitations.confidence_label in report
        assert ", ".join(finding_with_limitations.data_sources) in report
        assert finding_with_limitations.limitations[0].rstrip(".") in report
        assert finding_with_limitations.deep_link in report
    assert "Open the admin page" in html
    assert "Open Microsoft admin page" in md

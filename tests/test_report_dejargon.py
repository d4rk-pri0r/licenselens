"""Lock tests for the todo-22 executive-area de-jargon pass.

Locks the plain-language contracts of the report's exec surfaces:

* the hero never shows a raw zero-GUID or the legacy demo string
  ("Contoso Demo (dry-run)") as org identity — demo/dry-run renders as
  "Demo (synthetic data)";
* "assessment profile" never reaches customer-facing copy, and "rua/ruf"
  appears only with an explanation;
* the check-level "why it matters" wins over the matched capability blurb,
  so a log-shipping check never shows the generic "Passwords alone are not
  enough" capability copy;
* the check-specific sentence is render-only — the serialized scan JSON
  keeps its shape (the field is excluded from ``model_dump``).
"""

from __future__ import annotations

from pathlib import Path

from licenselens.catalog.expected_states import expected_state_map
from licenselens.engine.loader import load_checks
from licenselens.engine.runner_findings import base_finding
from licenselens.models import FindingStatus
from licenselens.report.bundle import build_report_bundle
from licenselens.report.html import write_html_report
from licenselens.report.viewmodel import build_belief_block, build_opening
from tests.report_fixtures import comprehensive_report, empty_report

ZERO_TENANT_ID = "00000000-0000-0000-0000-000000000000"
LEGACY_DEMO_NAME = "Contoso Demo (dry-run)"
DEMO_LABEL = "Demo (synthetic data)"


# ---------------------------------------------------------------------------
# Org identity: the hero never leaks the zero-GUID or legacy demo copy
# ---------------------------------------------------------------------------


def test_opening_maps_legacy_demo_name_to_clean_label() -> None:
    result = comprehensive_report().model_copy(
        update={"tenant_id": ZERO_TENANT_ID, "tenant_display_name": LEGACY_DEMO_NAME}
    )
    opening = build_opening(result)
    assert opening["tenant_name"] == DEMO_LABEL
    assert opening["tenant_id"] is None


def test_opening_suppresses_zero_guid_even_with_other_name() -> None:
    result = comprehensive_report().model_copy(
        update={"tenant_id": ZERO_TENANT_ID, "tenant_display_name": "Example Org"}
    )
    opening = build_opening(result)
    assert opening["tenant_name"] == "Example Org"
    assert opening["tenant_id"] is None


def test_opening_keeps_real_tenant_name_and_id() -> None:
    result = comprehensive_report()
    opening = build_opening(result)
    assert opening["tenant_name"] == result.tenant_display_name
    assert opening["tenant_id"] == result.tenant_id


def test_opening_neutral_fallback_untouched() -> None:
    opening = build_opening(empty_report())
    assert opening["tenant_name"] == "Your tenant"
    assert opening["tenant_id"] is None


def test_hero_renders_clean_demo_label(tmp_path: Path) -> None:
    result = comprehensive_report().model_copy(
        update={"tenant_id": ZERO_TENANT_ID, "tenant_display_name": LEGACY_DEMO_NAME}
    )
    html_path = write_html_report(result, tmp_path / "report.html")
    html = html_path.read_text(encoding="utf-8")
    # The hero opening line and the masthead Organization row carry the clean
    # label; the legacy demo string never appears as org identity.
    assert "Demo (synthetic data) &mdash; Security License Lens assessment" in html
    assert f"{LEGACY_DEMO_NAME} &mdash;" not in html
    assert "Organization <code>Demo (synthetic data)</code>" in html
    assert ZERO_TENANT_ID not in html
    assert "demo / dry-run" not in html

    bundle = build_report_bundle(result, tmp_path / "bundle")
    entry_html = bundle.entry_path.read_text(encoding="utf-8")
    assert '<span class="opening-identity__tenant">Demo (synthetic data)</span>' in entry_html
    assert "opening-identity__id" not in entry_html, "zero-GUID rendered as hero tenant id"


# ---------------------------------------------------------------------------
# "Why it matters": check-specific copy wins, generic capability copy never
# masquerades on unrelated checks
# ---------------------------------------------------------------------------


def test_belief_block_prefers_check_specific_why_it_matters() -> None:
    result = comprehensive_report()
    summary = result.capability_summaries[0]
    finding = result.findings[0].model_copy(
        update={"entitlements_used": [summary.id], "why_it_matters": "Check-specific reason."}
    )
    block = build_belief_block(finding, result.capability_summaries, expected_state_map())
    assert block["why_it_matters"]["capability"] == "Check-specific reason."


def test_belief_block_falls_back_to_capability_blurb() -> None:
    result = comprehensive_report()
    summary = result.capability_summaries[0]
    finding = result.findings[0].model_copy(
        update={"entitlements_used": [summary.id], "why_it_matters": ""}
    )
    block = build_belief_block(finding, result.capability_summaries, expected_state_map())
    assert block["why_it_matters"]["capability"] == summary.why_it_matters


def test_finding_why_it_matters_is_render_only() -> None:
    result = comprehensive_report()
    finding = result.findings[0].model_copy(update={"why_it_matters": "Render-only copy."})
    assert "why_it_matters" not in finding.model_dump(mode="json")
    serialized_finding = result.model_dump(mode="json")["findings"][0]
    assert "why_it_matters" not in serialized_finding


def test_check_specific_copy_flows_into_findings() -> None:
    checks = {check.id: check for check in load_checks()}
    logs_check = checks["id-logs-to-soc"]
    assert logs_check.why_it_matters
    finding = base_finding(
        logs_check,
        status=FindingStatus.SKIPPED,
        summary="Manual verification required.",
        owned={logs_check.required_capabilities[0]},
    )
    assert finding.why_it_matters == logs_check.why_it_matters
    # A genuine Conditional Access check carries no check-specific copy and
    # keeps falling back to the capability blurb in the view model.
    assert checks["id-ca-mfa-all-users"].why_it_matters == ""


# ---------------------------------------------------------------------------
# Customer-facing copy: no "assessment profile" jargon; rua/ruf only explained
# ---------------------------------------------------------------------------


def test_no_check_leaks_assessment_profile_jargon() -> None:
    for check in load_checks():
        for field in (
            check.customer_title,
            check.customer_summary,
            check.customer_next_step,
            check.remediation,
            check.expected_state,
            check.description,
            check.why_it_matters,
        ):
            assert "assessment profile" not in field, f"{check.id}: {field!r}"


def test_dmarc_contact_copy_explains_rua_ruf() -> None:
    checks = {check.id: check for check in load_checks()}
    agency = checks["exo-dmarc-agency-contact"]
    federal = checks["exo-dmarc-federal-contact"]
    assert "rua/ruf" in agency.customer_next_step
    assert "report recipients" in agency.customer_next_step, "rua/ruf must be explained"
    assert "assessment profile" not in agency.customer_next_step
    assert "assessment profile" not in agency.remediation
    assert "aggregate-report (rua)" in federal.customer_next_step
    assert "assessment profile" not in federal.customer_next_step
    assert "assessment profile" not in federal.remediation

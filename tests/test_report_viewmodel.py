"""Unit tests for the deterministic report view-model layer.

Locks the view-model contracts over the frozen ``report_fixtures`` inputs:

* **Determinism** — two calls on ``comprehensive_report()`` produce equal payloads.
* **Empty/sparse safety** — zero-finding and null-optional-field fixtures never
  crash and fall back to sensible empty values.
* **Field binding** — every belief-block slot maps to the correct model field,
  asserted against fixture data rather than hardcoded strings.
* **Data-driven posture** — the posture percent flows from the model, never a
  literal.
"""

from __future__ import annotations

from licenselens.catalog.expected_states import expected_state_map
from licenselens.report.viewmodel import (
    build_belief_block,
    build_constellation,
    build_opening,
    build_posture,
    build_provenance,
    build_sections,
    build_skip_reason,
)
from licenselens.schema_contracts import CollectionStatus, CollectionSummary, EvaluationMode
from tests.report_fixtures import (
    SCANNED_AT,
    comprehensive_report,
    empty_report,
    sparse_optional_fields_report,
)

# Workload order the constellation must respect (mirrors the module contract).
_WORKLOAD_ORDER: tuple[str, ...] = (
    "identity",
    "endpoint",
    "defender",
    "sentinel",
    "purview",
    "exchange",
    "collaboration",
    "teams",
    "power_platform",
    "power_bi",
    "intune",
    "azure",
)


def _workload_rank(entry: dict[str, str | int | None]) -> int:
    workload = entry["workload"]
    if workload is None or workload not in _WORKLOAD_ORDER:
        return len(_WORKLOAD_ORDER)
    return _WORKLOAD_ORDER.index(workload)


def test_posture_is_data_driven() -> None:
    result = comprehensive_report()
    posture = build_posture(result)
    assert posture["realized_percent"] == result.capability_rollup.realized_percent
    assert posture["realized_sentence"] == result.capability_rollup.realized_sentence


def test_posture_empty_report_safety() -> None:
    result = empty_report()
    posture = build_posture(result)
    assert posture["realized_percent"] == 0
    assert posture["realized_sentence"] == result.capability_rollup.realized_sentence
    assert isinstance(posture["realized_sentence"], str)
    assert posture["realized_sentence"]


def test_posture_deterministic() -> None:
    assert build_posture(comprehensive_report()) == build_posture(comprehensive_report())


def test_opening_carries_tenant_and_assessment_identity() -> None:
    result = comprehensive_report()
    opening = build_opening(result)
    assert opening["tenant_name"] == result.tenant_display_name
    assert opening["tenant_id"] == result.tenant_id
    assert opening["scanned_at"] == SCANNED_AT
    assert opening["assessment_identity"] == {
        "tool": result.tool,
        "tool_display_name": result.tool_display_name,
        "version": result.version,
    }


def test_opening_falls_back_to_neutral_tenant_name() -> None:
    result = empty_report()
    opening = build_opening(result)
    assert opening["tenant_name"] == "Your tenant"
    assert opening["tenant_id"] is None


def test_opening_surfaces_tenant_id_when_display_name_missing() -> None:
    result = comprehensive_report().model_copy(update={"tenant_display_name": None})
    opening = build_opening(result)
    assert opening["tenant_name"] == "Your tenant"
    assert opening["tenant_id"] == result.tenant_id


def test_opening_reuses_posture_values() -> None:
    result = comprehensive_report()
    opening = build_opening(result)
    assert opening["realized_percent"] == result.capability_rollup.realized_percent
    assert opening["realized_sentence"] == result.capability_rollup.realized_sentence


def test_opening_deterministic() -> None:
    assert build_opening(comprehensive_report()) == build_opening(comprehensive_report())


def test_constellation_deterministic() -> None:
    assert build_constellation(comprehensive_report()) == build_constellation(
        comprehensive_report()
    )


def test_constellation_entry_fields_bind_to_outcomes() -> None:
    result = comprehensive_report()
    outcome_by_id = {o.id: o for o in result.capability_outcomes}
    summary_by_id = {s.id: s for s in result.capability_summaries}
    constellation = build_constellation(result)
    assert len(constellation) == len(result.capability_outcomes)
    for entry in constellation:
        outcome = outcome_by_id[entry["id"]]
        summary = summary_by_id.get(outcome.id)
        assert entry["status"] == outcome.status
        assert entry["status_label"] == outcome.status_label
        assert entry["related_check_ids"] == len(outcome.related_check_ids)
        assert entry["name"] == (summary.name if summary else outcome.name)
        assert entry["plain_name"] == (summary.plain_name if summary else outcome.plain_name)


def test_constellation_ordered_by_workload_then_plain_name() -> None:
    constellation = build_constellation(comprehensive_report())
    ranks = [_workload_rank(entry) for entry in constellation]
    assert ranks == sorted(ranks)
    for index in range(len(constellation) - 1):
        left = constellation[index]
        right = constellation[index + 1]
        if _workload_rank(left) == _workload_rank(right):
            assert left["plain_name"] <= right["plain_name"]


def test_sections_deterministic() -> None:
    assert build_sections(comprehensive_report()) == build_sections(comprehensive_report())


def test_sections_empty_report_safety() -> None:
    sections = build_sections(empty_report())
    assert sections["A"]["rollup"]["you_own"] == 0
    assert sections["B"] == []
    assert sections["C"] == []
    assert sections["D"] == []
    assert sections["E"]["findings"] == []
    assert sections["E"]["filters"] == {
        "status": [],
        "severity": [],
        "confidence": [],
        "evaluation_mode": [],
        "pack": [],
        "workload": [],
    }


def test_belief_block_field_binding() -> None:
    result = comprehensive_report()
    finding = result.findings[0]
    expected_by_check_id = expected_state_map()
    block = build_belief_block(finding, result.capability_summaries, expected_by_check_id)
    assert block["observed"] == {"summary": finding.summary, "evidence": finding.evidence}
    assert block["summary_line"] == finding.customer_summary
    assert block["expected"] == expected_by_check_id[finding.check_id]
    assert block["why_it_matters"]["severity"] == finding.severity.value
    assert block["why_it_matters"]["value_impact"] == finding.value_impact.value
    assert block["why_it_matters"]["blast_radius"] == finding.blast_radius.value
    assert block["recommended_action"] == finding.customer_next_step
    assert block["evidence"]["data_sources"] == finding.data_sources
    assert block["evidence"]["confidence_label"] == finding.confidence_label
    assert block["evidence"]["limitations"] == finding.limitations
    assert block["admin_destination"] == finding.deep_link
    # Fixture findings carry no entitlements_used -> capability slots fall back.
    assert block["why_it_matters"]["capability"] == ""


def test_belief_block_expected_ignores_capability_match() -> None:
    result = comprehensive_report()
    summary = result.capability_summaries[0]
    finding = result.findings[0].model_copy(update={"entitlements_used": [summary.id]})
    block = build_belief_block(finding, result.capability_summaries, expected_state_map())
    assert block["expected"] == expected_state_map()[finding.check_id]
    assert block["expected"] != summary.outcome
    assert block["why_it_matters"]["capability"] == summary.why_it_matters


def test_belief_block_expected_not_reported_for_unknown_check() -> None:
    result = comprehensive_report()
    finding = result.findings[0].model_copy(update={"check_id": "check-not-in-catalog"})
    block = build_belief_block(finding, result.capability_summaries, expected_state_map())
    assert block["expected"] == "Not reported"


def test_belief_block_recommended_action_falls_back_to_remediation() -> None:
    result = comprehensive_report()
    finding = result.findings[0].model_copy(
        update={"customer_next_step": "", "remediation": "Remediate it."}
    )
    block = build_belief_block(finding, result.capability_summaries, expected_state_map())
    assert block["recommended_action"] == "Remediate it."


def test_belief_block_sparse_optional_fields() -> None:
    result = sparse_optional_fields_report()
    finding = result.findings[0]
    block = build_belief_block(finding, result.capability_summaries, expected_state_map())
    assert block["admin_destination"] is None
    assert block["recommended_action"] == ""
    assert block["evidence"]["data_sources"] == []
    assert block["evidence"]["limitations"] == []
    assert block["observed"]["evidence"] == {}
    assert block["observed"]["summary"] == finding.summary
    assert block["summary_line"] == finding.customer_summary
    assert block["expected"] == "Not reported"


# ---------------------------------------------------------------------------
# Provenance footer payload (todo 20)
# ---------------------------------------------------------------------------


def test_provenance_legend_derives_from_findings_not_a_fixed_list() -> None:
    result = comprehensive_report()
    payload = build_provenance(result)
    assert [entry["mode"] for entry in payload["mode_legend"]] == ["direct"]


def test_provenance_legend_lists_only_present_modes_in_canonical_order() -> None:
    result = comprehensive_report()
    finding = result.findings[0]
    result.findings = [
        finding.model_copy(update={"evaluation_mode": EvaluationMode.PROXY}),
        finding.model_copy(update={"evaluation_mode": EvaluationMode.MANUAL}),
        finding.model_copy(update={"evaluation_mode": EvaluationMode.DIRECT}),
    ]
    legend = build_provenance(result)["mode_legend"]
    assert [entry["mode"] for entry in legend] == ["direct", "proxy", "manual"]
    assert [entry["label"] for entry in legend] == [
        "Direct read",
        "Approximated (proxy) — verify in portal",
        "Manual review",
    ]


def test_provenance_methodology_tracks_present_modes() -> None:
    result = comprehensive_report()
    finding = result.findings[0]
    result.findings = [finding.model_copy(update={"evaluation_mode": EvaluationMode.PROXY})]
    methodology = build_provenance(result)["methodology"]
    assert "Secure Score" in methodology
    assert "Graph and PowerShell" not in methodology
    assert "manual review" not in methodology


def test_provenance_methodology_covers_all_three_paths() -> None:
    result = comprehensive_report()
    finding = result.findings[0]
    result.findings = [
        finding.model_copy(update={"evaluation_mode": EvaluationMode.DIRECT}),
        finding.model_copy(update={"evaluation_mode": EvaluationMode.PROXY}),
        finding.model_copy(update={"evaluation_mode": EvaluationMode.MANUAL}),
    ]
    methodology = build_provenance(result)["methodology"]
    assert "Graph and PowerShell" in methodology
    assert "Secure Score approximates" in methodology
    assert "manual review covers settings no API exposes" in methodology


def test_provenance_empty_report_safety() -> None:
    payload = build_provenance(empty_report())
    assert payload["mode_legend"] == []
    assert payload["methodology"] == "No findings were evaluated in this scan."


def test_provenance_identity_synthetic_fallback_for_nameless_dry_run() -> None:
    result = empty_report()
    identity = build_provenance(result)["identity"]
    assert identity["name"] == "demo (synthetic)"
    assert identity["scanned_at"] == SCANNED_AT
    assert identity["display_scanned_at"] == result.display_scanned_at


def test_provenance_identity_prefers_tenant_display_name() -> None:
    result = comprehensive_report()
    identity = build_provenance(result)["identity"]
    assert identity["name"] == result.tenant_display_name


def test_provenance_identity_neutral_fallback_for_nameless_live_scan() -> None:
    result = empty_report()
    result.scan_mode = "live"
    identity = build_provenance(result)["identity"]
    assert identity["name"] == "Your tenant"


def test_provenance_sampling_flags_partial_collections() -> None:
    result = empty_report()
    result.collection_summaries = [
        CollectionSummary(collector="apps", status=CollectionStatus.SUCCESS),
        CollectionSummary(collector="signins", status=CollectionStatus.PARTIAL),
    ]
    sampling = build_provenance(result)["sampling"]
    assert sampling["sampled"] is True
    assert "sampled or truncated" in sampling["text"]


def test_provenance_sampling_enumerated_when_all_complete() -> None:
    result = empty_report()
    result.collection_summaries = [
        CollectionSummary(collector="apps", status=CollectionStatus.SUCCESS),
    ]
    sampling = build_provenance(result)["sampling"]
    assert sampling["sampled"] is False
    assert "enumerated in full" in sampling["text"]


def test_provenance_sampling_discloses_when_nothing_recorded() -> None:
    sampling = build_provenance(empty_report())["sampling"]
    assert sampling["sampled"] is False
    assert sampling["text"] == "No sampling or truncation recorded for this scan."


def test_provenance_deterministic() -> None:
    result = comprehensive_report()
    assert build_provenance(result) == build_provenance(result)


# ---------------------------------------------------------------------------
# Skip reason (todo 21)
# ---------------------------------------------------------------------------


def test_skip_reason_binds_finding_summary_for_skipped() -> None:
    """A skipped finding's rationale is its own summary text — never invented."""
    result = comprehensive_report()
    finding = next(f for f in result.findings if f.status.value == "skipped")
    block = build_belief_block(finding, result.capability_summaries, expected_state_map())
    assert block["skip_reason"] == finding.summary
    assert block["skip_reason"], "skipped finding produced an empty skip reason"


def test_skip_reason_falls_back_to_limitations_when_summary_empty() -> None:
    """With no summary, the rationale reuses the existing limitations text."""
    result = comprehensive_report()
    finding = next(f for f in result.findings if f.status.value == "skipped")
    bare = finding.model_copy(update={"summary": ""})
    assert build_skip_reason(bare) == "; ".join(
        limit.rstrip(".") for limit in finding.limitations
    )


def test_skip_reason_empty_for_non_skipped_findings() -> None:
    result = comprehensive_report()
    for finding in result.findings:
        if finding.status.value == "skipped":
            continue
        block = build_belief_block(finding, result.capability_summaries, expected_state_map())
        assert block["skip_reason"] == "", (
            f"non-skipped {finding.check_id} must carry an empty skip_reason"
        )

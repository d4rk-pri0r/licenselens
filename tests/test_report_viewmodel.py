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

from licenselens.report.viewmodel import (
    build_belief_block,
    build_constellation,
    build_posture,
    build_sections,
)
from tests.report_fixtures import (
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
    block = build_belief_block(finding, result.capability_summaries)
    assert block["observed"] == {"summary": finding.summary, "evidence": finding.evidence}
    assert block["why_it_matters"]["severity"] == finding.severity.value
    assert block["why_it_matters"]["value_impact"] == finding.value_impact.value
    assert block["why_it_matters"]["blast_radius"] == finding.blast_radius.value
    assert block["recommended_action"] == finding.customer_next_step
    assert block["evidence"]["data_sources"] == finding.data_sources
    assert block["evidence"]["confidence_label"] == finding.confidence_label
    assert block["evidence"]["limitations"] == finding.limitations
    assert block["admin_destination"] == finding.deep_link
    # Fixture findings carry no entitlements_used -> capability slots fall back.
    assert block["expected"] == ""
    assert block["why_it_matters"]["capability"] == ""


def test_belief_block_expected_from_matching_capability() -> None:
    result = comprehensive_report()
    summary = result.capability_summaries[0]
    finding = result.findings[0].model_copy(update={"entitlements_used": [summary.id]})
    block = build_belief_block(finding, result.capability_summaries)
    assert block["expected"] == summary.outcome
    assert block["why_it_matters"]["capability"] == summary.why_it_matters


def test_belief_block_recommended_action_falls_back_to_remediation() -> None:
    result = comprehensive_report()
    finding = result.findings[0].model_copy(
        update={"customer_next_step": "", "remediation": "Remediate it."}
    )
    block = build_belief_block(finding, result.capability_summaries)
    assert block["recommended_action"] == "Remediate it."


def test_belief_block_sparse_optional_fields() -> None:
    result = sparse_optional_fields_report()
    finding = result.findings[0]
    block = build_belief_block(finding, result.capability_summaries)
    assert block["admin_destination"] is None
    assert block["recommended_action"] == ""
    assert block["evidence"]["data_sources"] == []
    assert block["evidence"]["limitations"] == []
    assert block["observed"]["evidence"] == {}
    assert block["observed"]["summary"] == finding.summary

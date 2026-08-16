"""Wave 3 Purview governance direct/manual evaluator coverage."""

from __future__ import annotations

from licenselens.collectors.power_data import bundle_to_evidence
from licenselens.collectors.power_data_demo import demo_power_data_evidence
from licenselens.collectors.power_data_models import (
    PURVIEW_ADAPTER,
    PowerDataBundle,
)
from licenselens.collectors.power_data_normalize import normalize_adapter_payload
from licenselens.engine.evaluate import (
    evaluate_pur_default_and_mandatory_labels,
    evaluate_pur_retention_policy_coverage,
    evaluate_pur_sensitivity_auto_labeling,
    evaluate_pur_sensitivity_labels_published,
)
from licenselens.engine.registry import default_registry
from licenselens.evaluators.purview_manual import (
    evaluate_pur_communication_compliance_readiness,
    evaluate_pur_ediscovery_readiness,
    evaluate_pur_insider_risk_readiness,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload
from licenselens.schema_contracts import JsonValue


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.PURVIEW)


def _surface(
    name: str,
    *,
    status: str = "ok",
    items: list[dict[str, JsonValue]] | None = None,
    reason: str = "",
    raw_count: int | None = None,
) -> dict[str, JsonValue]:
    rows = items or []
    return {
        "surface": name,
        "status": status,
        "reason": reason,
        "raw_count": raw_count if raw_count is not None else len(rows),
        "items": rows,
    }


def _item(
    name: str,
    *,
    enabled: bool = True,
    properties: dict[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    return {
        "name": name,
        "identity": name,
        "kind": "custom",
        "enabled": enabled,
        "properties": properties or {},
        "assignments": [],
    }


def _power_evidence(surfaces: dict[str, JsonValue]) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "adapter": PURVIEW_ADAPTER,
        "module": "ExchangeOnlineManagement",
        "collection": "purview_governance",
        "surfaces": surfaces,
    }
    adapter = normalize_adapter_payload(payload, adapter=PURVIEW_ADAPTER)
    bundle = PowerDataBundle(adapters={PURVIEW_ADAPTER: adapter})
    return bundle_to_evidence(bundle)


def test_demo_direct_matrix_ok() -> None:
    evidence = demo_power_data_evidence()
    published = evaluate_pur_sensitivity_labels_published(
        _check("pur-sensitivity-labels-published"), evidence
    )
    assert published.status is FindingStatus.OK
    assert published.evidence["published"] is True
    assert published.confidence.value == "high"

    default_mandatory = evaluate_pur_default_and_mandatory_labels(
        _check("pur-default-and-mandatory-labels"), evidence
    )
    assert default_mandatory.status is FindingStatus.OK
    assert default_mandatory.evidence["default_label"] is True
    assert default_mandatory.evidence["mandatory_labeling"] is True

    retention = evaluate_pur_retention_policy_coverage(
        _check("pur-retention-policy-coverage"), evidence
    )
    assert retention.status is FindingStatus.OK
    assert retention.evidence["retention_policies"] >= 1

    # Demo fixture has label policies but no explicit auto-labeling marker.
    auto = evaluate_pur_sensitivity_auto_labeling(_check("pur-sensitivity-auto-labeling"), evidence)
    assert auto.status is FindingStatus.GAP


def test_default_and_mandatory_labels_ok_from_settings() -> None:
    evidence = _power_evidence(
        {
            "label_policies": _surface(
                "label_policies",
                items=[
                    _item(
                        "Global",
                        properties={
                            "Settings": ["DefaultLabelId:conf", "Mandatory:true"],
                        },
                    )
                ],
            ),
        }
    )
    result = evaluate_pur_default_and_mandatory_labels(
        _check("pur-default-and-mandatory-labels"), evidence
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["default_label"] is True
    assert result.evidence["mandatory_labeling"] is True


def test_default_and_mandatory_labels_ok_from_explicit_props() -> None:
    evidence = _power_evidence(
        {
            "label_policies": _surface(
                "label_policies",
                items=[
                    _item(
                        "Global",
                        properties={"DefaultLabelId": "conf", "Mandatory": True},
                    )
                ],
            ),
        }
    )
    result = evaluate_pur_default_and_mandatory_labels(
        _check("pur-default-and-mandatory-labels"), evidence
    )
    assert result.status is FindingStatus.OK


def test_default_and_mandatory_labels_neither_gap() -> None:
    evidence = _power_evidence(
        {
            "label_policies": _surface(
                "label_policies",
                items=[_item("Global", properties={"Enabled": True})],
            ),
        }
    )
    result = evaluate_pur_default_and_mandatory_labels(
        _check("pur-default-and-mandatory-labels"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.status is not FindingStatus.OK
    assert result.evidence["default_label"] is False
    assert result.evidence["mandatory_labeling"] is False


def test_default_and_mandatory_labels_absent_gap() -> None:
    evidence = _power_evidence(
        {
            "label_policies": _surface(
                "label_policies",
                reason="absent: no label_policies configured",
            ),
        }
    )
    result = evaluate_pur_default_and_mandatory_labels(
        _check("pur-default-and-mandatory-labels"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence["absent"] is True


def test_default_and_mandatory_labels_only_default_partial() -> None:
    evidence = _power_evidence(
        {
            "label_policies": _surface(
                "label_policies",
                items=[_item("Global", properties={"Settings": ["DefaultLabelId:conf"]})],
            ),
        }
    )
    result = evaluate_pur_default_and_mandatory_labels(
        _check("pur-default-and-mandatory-labels"), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence["default_label"] is True
    assert result.evidence["mandatory_labeling"] is False


def test_auto_labeling_ok_when_marker_present() -> None:
    evidence = _power_evidence(
        {
            "sensitivity_labels": _surface(
                "sensitivity_labels",
                items=[_item("Confidential")],
            ),
            "label_policies": _surface(
                "label_policies",
                items=[_item("Global", properties={"DefaultLabelId": "conf"})],
            ),
        }
    )
    result = evaluate_pur_sensitivity_auto_labeling(
        _check("pur-sensitivity-auto-labeling"), evidence
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["auto_labeling"] is True


def test_unpublished_labels_gap() -> None:
    evidence = _power_evidence(
        {
            "sensitivity_labels": _surface(
                "sensitivity_labels",
                items=[_item("Confidential")],
            ),
            "label_policies": _surface(
                "label_policies",
                reason="absent: no label_policies configured",
            ),
        }
    )
    result = evaluate_pur_sensitivity_labels_published(
        _check("pur-sensitivity-labels-published"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence["unpublished"] is True


def test_absent_labels_gap_distinct_from_denied() -> None:
    absent = evaluate_pur_sensitivity_labels_published(
        _check("pur-sensitivity-labels-published"),
        _power_evidence(
            {
                "sensitivity_labels": _surface(
                    "sensitivity_labels",
                    reason="absent: no sensitivity_labels configured",
                ),
                "label_policies": _surface(
                    "label_policies",
                    reason="absent: no label_policies configured",
                ),
            }
        ),
    )
    assert absent.status is FindingStatus.GAP
    assert absent.evidence["absent"] is True

    denied = evaluate_pur_sensitivity_labels_published(
        _check("pur-sensitivity-labels-published"),
        _power_evidence(
            {
                "sensitivity_labels": _surface("sensitivity_labels", status="denied"),
                "label_policies": _surface("label_policies", status="denied"),
            }
        ),
    )
    assert denied.status is FindingStatus.PARTIAL
    assert denied.status is not FindingStatus.OK
    assert denied.evidence["denied"] is True


def test_denied_compliance_session_never_passes() -> None:
    for evaluator, check_id in (
        (evaluate_pur_retention_policy_coverage, "pur-retention-policy-coverage"),
        (evaluate_pur_sensitivity_labels_published, "pur-sensitivity-labels-published"),
        (evaluate_pur_default_and_mandatory_labels, "pur-default-and-mandatory-labels"),
    ):
        result = evaluator(
            _check(check_id),
            _power_evidence(
                {
                    "retention_policies": _surface("retention_policies", status="denied"),
                    "retention_rules": _surface("retention_rules", status="denied"),
                    "sensitivity_labels": _surface("sensitivity_labels", status="denied"),
                    "label_policies": _surface("label_policies", status="denied"),
                }
            ),
        )
        assert result.status is not FindingStatus.OK
        assert result.status is FindingStatus.PARTIAL


def test_missing_bundle_is_unreadable_not_ok() -> None:
    for evaluator, check_id in (
        (evaluate_pur_sensitivity_labels_published, "pur-sensitivity-labels-published"),
        (evaluate_pur_retention_policy_coverage, "pur-retention-policy-coverage"),
        (evaluate_pur_default_and_mandatory_labels, "pur-default-and-mandatory-labels"),
    ):
        result = evaluator(_check(check_id), {})
        assert result.status is FindingStatus.PARTIAL
        assert result.status is not FindingStatus.OK


def test_malformed_bundle_is_partial_not_error() -> None:
    result = evaluate_pur_sensitivity_labels_published(
        _check("pur-sensitivity-labels-published"),
        {"power_data_bundle": {"adapters": "not-a-dict"}},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK


def test_retention_policies_without_rules_partial() -> None:
    evidence = _power_evidence(
        {
            "retention_policies": _surface(
                "retention_policies",
                items=[_item("7-year mailbox")],
            ),
            "retention_rules": _surface(
                "retention_rules",
                reason="absent: no retention_rules configured",
            ),
        }
    )
    result = evaluate_pur_retention_policy_coverage(
        _check("pur-retention-policy-coverage"), evidence
    )
    assert result.status is FindingStatus.PARTIAL


def test_retention_absent_gap() -> None:
    evidence = _power_evidence(
        {
            "retention_policies": _surface(
                "retention_policies",
                reason="absent: no retention_policies configured",
            ),
            "retention_rules": _surface(
                "retention_rules",
                reason="absent: no retention_rules configured",
            ),
        }
    )
    result = evaluate_pur_retention_policy_coverage(
        _check("pur-retention-policy-coverage"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence["absent"] is True


def test_manual_checks_emit_skipped_with_guidance() -> None:
    for evaluator in (
        evaluate_pur_insider_risk_readiness,
        evaluate_pur_communication_compliance_readiness,
        evaluate_pur_ediscovery_readiness,
    ):
        result = evaluator(_check("pur-manual"), {})
        assert result.status is FindingStatus.SKIPPED
        assert result.evidence.get("manual") is True
        assert result.evidence.get("evaluation_mode") == "manual"
        assert result.limitations


def test_new_checks_registered_in_evaluators_and_registry() -> None:
    new_ids = {
        "pur-sensitivity-labels-published",
        "pur-sensitivity-auto-labeling",
        "pur-retention-policy-coverage",
        "pur-default-and-mandatory-labels",
        "pur-insider-risk-readiness",
        "pur-communication-compliance-readiness",
        "pur-ediscovery-readiness",
    }
    registry = default_registry()
    assert new_ids <= set(registry.evaluators)
    for check_id in new_ids:
        entry = registry.evaluator_for(check_id)
        assert entry.evaluate is not None
        assert entry.input_models


def test_direct_checks_are_not_proxy_classified() -> None:
    evidence = demo_power_data_evidence()
    published = evaluate_pur_sensitivity_labels_published(
        _check("pur-sensitivity-labels-published"), evidence
    )
    assert published.confidence.value == "high"
    assert not any("proxy" in s.lower() for s in published.data_sources)
    assert not any("secureScore" in s for s in published.data_sources)

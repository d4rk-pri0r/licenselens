"""WS4-B: protective-plan assignment counts."""

from __future__ import annotations

from licenselens.auth import AuthContext, AuthMode
from licenselens.collectors.conditional_access import DEMO_CA_POLICIES
from licenselens.engine.evaluate import evaluate_protective_plan_assignment
from licenselens.engine.registry import default_registry
from licenselens.engine.runner import run_scan
from licenselens.evaluators.identity_ca_risk import evaluate_ca_high_risk_users
from licenselens.models import CheckDefinition, FindingStatus, Workload
from licenselens.schema_contracts import EvaluationMode


def _check() -> CheckDefinition:
    return CheckDefinition(
        id="id-protective-plan-assignment",
        title="assignment",
        workload=Workload.IDENTITY,
    )


def _assignment(*, assigned: int, enabled: int = 100, method: str = "assignedPlans") -> dict:
    return {
        "enabled_member_users": enabled,
        "by_capability": {
            "identity_protection": {"assigned_users": assigned, "method": method},
            "defender_endpoint_p2": {"assigned_users": assigned, "method": method},
        },
    }


def test_assignment_ok_at_87_of_100() -> None:
    result = evaluate_protective_plan_assignment(
        _check(),
        {
            "license_assignment": _assignment(assigned=87),
            "owned_capabilities": ["identity_protection", "defender_endpoint_p2"],
        },
    )
    assert result.status is FindingStatus.OK


def test_assignment_gap_below_half() -> None:
    result = evaluate_protective_plan_assignment(
        _check(),
        {
            "license_assignment": _assignment(assigned=1, enabled=25),
            "owned_capabilities": ["identity_protection"],
        },
    )
    assert result.status is FindingStatus.GAP


def test_assignment_partial_between() -> None:
    result = evaluate_protective_plan_assignment(
        _check(),
        {
            "license_assignment": _assignment(assigned=60),
            "owned_capabilities": ["identity_protection"],
        },
    )
    assert result.status is FindingStatus.PARTIAL


def test_assignment_missing_is_error() -> None:
    result = evaluate_protective_plan_assignment(_check(), {})
    assert result.status is FindingStatus.ERROR


def test_assignment_unavailable_is_error() -> None:
    result = evaluate_protective_plan_assignment(
        _check(),
        {
            "license_assignment": {
                "enabled_member_users": 100,
                "by_capability": {
                    "identity_protection": {"assigned_users": None, "method": "unavailable"}
                },
            },
            "owned_capabilities": ["identity_protection"],
        },
    )
    assert result.status is FindingStatus.ERROR


def test_registered_as_direct() -> None:
    entry = default_registry().evaluators["id-protective-plan-assignment"]
    assert entry.evaluation_mode is EvaluationMode.DIRECT


def test_demo_assignment_is_ok() -> None:
    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    finding = next(f for f in result.findings if f.check_id == "id-protective-plan-assignment")
    assert finding.status is FindingStatus.OK
    card = next(c for c in result.capability_summaries if c.id == "identity_protection")
    assert card.assigned_users == 87
    assert card.enabled_users == 100


def test_high_risk_users_notes_protected_population() -> None:
    base = evaluate_ca_high_risk_users(
        CheckDefinition(id="id-ca-high-risk-users", title="risk", workload=Workload.IDENTITY),
        {"ca_policies": DEMO_CA_POLICIES},
    )
    annotated = evaluate_ca_high_risk_users(
        CheckDefinition(id="id-ca-high-risk-users", title="risk", workload=Workload.IDENTITY),
        {
            "ca_policies": DEMO_CA_POLICIES,
            "license_assignment": _assignment(assigned=87),
        },
    )
    assert annotated.status is base.status
    assert annotated.evidence["protected_population"]["assigned_users"] == 87
    assert any("Entra ID P2" in note for note in annotated.limitations)

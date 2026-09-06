"""WS2-B: unobservable consumption entitlements yield error, never not_licensed."""

from __future__ import annotations

import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.collectors.consumption_entitlements import DEMO_WORKSPACE_RESOURCE_ID
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import _evaluate_check
from licenselens.models import Confidence, FindingStatus
from tests.fake_clients import FakeArmClient, FakeGraphClient, PathHandler, error, ok

_SUB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_WS = (
    f"subscriptions/{_SUB}/resourceGroups/rg-1/providers/"
    "Microsoft.OperationalInsights/workspaces/lab-sentinel-ws"
)
_ONBOARDING = f"{_WS}/providers/Microsoft.SecurityInsights/onboardingStates/default"
_PRICINGS = f"subscriptions/{_SUB}/providers/Microsoft.Security/pricings"


def _auth() -> AuthContext:
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="test-tenant")


def _arm(
    *,
    onboarding: PathHandler | None = None,
    workspace: PathHandler | None = None,
    pricings: PathHandler | None = None,
) -> FakeArmClient:
    arm = FakeArmClient()
    arm.register_get(_ONBOARDING, onboarding or error(404))
    arm.register_get(_WS, workspace or error(404))
    arm.register_get(_PRICINGS, pricings or error(404))
    return arm


def test_unknown_entitlement_yields_error_not_not_licensed() -> None:
    checks = {c.id: c for c in load_checks() if c.enabled}
    check = checks["sen-analytics-rule-coverage"]
    finding = _evaluate_check(check, set(), {}, entitlement_unknown={"microsoft_sentinel"})
    assert finding.status is FindingStatus.ERROR
    assert finding.confidence is Confidence.LOW
    assert finding.evidence["entitlement_unknown"] == ["microsoft_sentinel"]
    assert finding.data_sources == ["arm:entitlementObservation"]
    assert finding.customer_summary == (
        "We could not tell whether you use this Azure capability because the "
        "Azure read was denied or no Azure scope was supplied."
    )
    assert finding.customer_next_step.index("docs/permissions.md") >= 0
    assert "Microsoft Sentinel Reader" in finding.customer_next_step


def test_empty_unknown_still_not_licensed() -> None:
    """Control — locks the empty default (green on HEAD, must stay green)."""
    checks = {c.id: c for c in load_checks() if c.enabled}
    for check_id in ("sen-analytics-rule-coverage", "az-defender-plan-enabled"):
        finding = _evaluate_check(checks[check_id], set(), {})
        assert finding.status is FindingStatus.NOT_LICENSED, check_id


def test_live_arm_403_sen_findings_are_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exact prior bug: E5 SKUs + workspace id + ARM 403 → sen-* error, never not_licensed."""
    from licenselens.engine.runner import run_scan

    arm = _arm(onboarding=error(403), workspace=error(403), pricings=error(403))
    monkeypatch.setattr("licenselens.collectors.arm.ArmClient", lambda _auth, **_kw: arm)
    graph = FakeGraphClient()
    graph.register_list("/organization", ok({"value": [{"id": "t-3", "displayName": "DeniedCo"}]}))
    graph.register_list(
        "/subscribedSkus",
        ok(
            {
                "value": [
                    {
                        "skuId": "e5",
                        "skuPartNumber": "SPE_E5",
                        "capabilityStatus": "Enabled",
                        "consumedUnits": 50,
                        "prepaidUnits": {"enabled": 100},
                        "servicePlans": [
                            {"servicePlanName": "AAD_PREMIUM_P2", "provisioningStatus": "Success"}
                        ],
                    }
                ]
            }
        ),
    )
    graph.register_list("/identity/conditionalAccess/policies", ok({"value": []}))
    graph.register_list("/roleManagement/directory/roleAssignments", ok({"value": []}))
    graph.register_list("/roleManagement/directory/roleEligibilitySchedules", ok({"value": []}))
    graph.register_list("/auditLogs/signIns", ok({"value": []}))
    graph.register_get(
        "/security/secureScores",
        ok(
            {
                "value": [
                    {
                        "id": "ss-1",
                        "currentScore": 50.0,
                        "maxScore": 100.0,
                        "controlScores": [],
                    }
                ]
            }
        ),
    )
    graph.register_get(
        "/policies/identitySecurityDefaultsEnforcementPolicy",
        ok({"id": "sd-1", "isEnabled": True}),
    )
    graph.register_list("/identityGovernance/accessReviews/definitions", ok({"value": []}))
    monkeypatch.setattr("licenselens.engine.runner.GraphClient", lambda _auth, **_kw: graph)
    monkeypatch.setattr(
        "licenselens.collectors.runtime.collect_mde_machine_summary",
        lambda _auth: {
            "onboarded_machines": 50,
            "sample_size": 50,
            "count_method": "test",
            "truncated": False,
        },
    )
    monkeypatch.setattr(
        "licenselens.collectors.runtime.collect_sentinel_bundle",
        lambda _auth, _wid: {
            "sentinel_rules": {"total_rules": 0},
            "sentinel_ueba": {},
            "workspace_resource_id": _wid,
        },
    )
    monkeypatch.setattr(
        "licenselens.collectors.workspace_discover.discover_sentinel_workspaces",
        lambda _auth: [],
    )

    result = run_scan(
        _auth(), dry_run=False, workspace_resource_id=f"/{_WS}", allow_email_proxy=True
    )
    assert result.scan_mode == "live"
    sen = [f for f in result.findings if f.check_id.startswith("sen-")]
    assert sen, "fixture must produce sen-* findings"
    assert all(f.status is FindingStatus.ERROR for f in sen), [
        (f.check_id, f.status.value) for f in sen
    ]
    assert not any(f.status is FindingStatus.NOT_LICENSED for f in sen)
    az = [f for f in result.findings if f.check_id.startswith("az-")]
    assert all(f.status is FindingStatus.ERROR for f in az), [
        (f.check_id, f.status.value) for f in az
    ]
    assert "microsoft_sentinel" not in result.owned_capabilities
    assert any("Microsoft Sentinel entitlement not assessed" in w for w in result.warnings)


def test_summary_consumption_lists_observed_resource() -> None:
    from licenselens.engine.runner import run_scan

    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    by_id = {s.id: s for s in result.capability_summaries}
    sentinel = by_id["microsoft_sentinel"]
    assert sentinel.entitlement_kind == "consumption"
    assert sentinel.observed_resources == [DEMO_WORKSPACE_RESOURCE_ID]
    log_analytics = by_id["log_analytics"]
    assert log_analytics.entitlement_kind == "consumption"
    assert log_analytics.observed_resources == [DEMO_WORKSPACE_RESOURCE_ID]
    conditional_access = by_id["conditional_access"]
    assert conditional_access.entitlement_kind == "included"
    assert conditional_access.observed_resources == []


def test_docs_describe_consumption_observation() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    model = (root / "docs" / "methodology" / "entitlement-model.md").read_text(encoding="utf-8")
    assert "Consumption entitlements are observed, not licensed" in model
    assert "onboardingStates" in model
    assert "Microsoft Sentinel Reader" in model
    assert "Security Reader" in model
    for rel in ("docs/limitations.md", "docs/methodology/limitations.md", "docs/package-readme.md"):
        text = (root / rel).read_text(encoding="utf-8")
        assert "undetermined" in text, rel
    audit = (root / "audit" / "check-semantic-audit.md").read_text(encoding="utf-8")
    assert "Entitlement Dependency: Microsoft Sentinel" not in audit
    assert audit.count("observed via ARM onboardingStates (0.5)") == 5
    entitlement_audit = (root / "audit" / "entitlement-audit.md").read_text(encoding="utf-8")
    assert "onboardingStates" in entitlement_audit
    assert "error" in entitlement_audit

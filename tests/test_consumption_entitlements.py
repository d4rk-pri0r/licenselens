"""Consumption entitlement observation (WS2-A): observed in Azure, not SKU-unlocked."""

from __future__ import annotations

import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.catalog.loader import load_capabilities
from licenselens.collectors.consumption_entitlements import observe_consumption_entitlements
from tests.fake_clients import FakeArmClient, PathHandler, error, ok

_SUB = "11111111-2222-3333-4444-555555555555"
_WS = (
    f"subscriptions/{_SUB}/resourceGroups/rg-1/providers/"
    "Microsoft.OperationalInsights/workspaces/ws-1"
)
_ONBOARDING = f"{_WS}/providers/Microsoft.SecurityInsights/onboardingStates/default"
_PRICINGS = f"subscriptions/{_SUB}/providers/Microsoft.Security/pricings"

_ONBOARDING_200 = {
    "id": f"{_ONBOARDING}",
    "name": "default",
    "type": "Microsoft.SecurityInsights/onboardingStates",
    "properties": {"customerManagedKey": False},
}


def _auth() -> AuthContext:
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="test-tenant")


_NOT_FOUND: PathHandler = error(404)


def _arm(
    *,
    onboarding: PathHandler = _NOT_FOUND,
    workspace: PathHandler = _NOT_FOUND,
    pricings: PathHandler = _NOT_FOUND,
) -> FakeArmClient:
    arm = FakeArmClient()
    arm.register_get(_ONBOARDING, onboarding)
    arm.register_get(_WS, workspace)
    arm.register_get(_PRICINGS, pricings)
    return arm


def test_sentinel_onboarded_owned() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=f"/{_WS}",
        subscription_id=None,
        arm_client=_arm(onboarding=ok(_ONBOARDING_200)),
    )
    assert result.owned == {"microsoft_sentinel"}
    assert result.unknown == frozenset()
    assert result.warnings == ()
    assert result.evidence["microsoft_sentinel"]["status"] == 200


def test_sentinel_404_not_owned() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=f"/{_WS}",
        subscription_id=None,
        arm_client=_arm(onboarding=error(404)),
    )
    assert "microsoft_sentinel" not in result.owned
    assert "microsoft_sentinel" not in result.unknown
    assert result.evidence["microsoft_sentinel"]["status"] == 404


def test_sentinel_403_unknown() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=f"/{_WS}",
        subscription_id=None,
        arm_client=_arm(onboarding=error(403)),
    )
    assert "microsoft_sentinel" not in result.owned
    assert "microsoft_sentinel" in result.unknown
    assert any("Microsoft Sentinel" in w for w in result.warnings)


def test_network_error_unknown() -> None:
    from licenselens.errors import GraphError

    def _boom(_path: str, _params: dict | None) -> dict:
        raise GraphError("ARM network error: connection reset")

    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=f"/{_WS}",
        subscription_id=None,
        arm_client=_arm(onboarding=_boom),
    )
    assert "microsoft_sentinel" in result.unknown
    assert "microsoft_sentinel" not in result.owned


_WORKSPACE_200 = {
    "id": f"/{_WS}",
    "name": "ws-1",
    "properties": {
        "customerId": "5b02755b-5bf4-430c-9487-45502a2a7e62",
        "provisioningState": "Succeeded",
        "sku": {"name": "PerGB2018"},
        "retentionInDays": 90,
    },
}


def test_log_analytics_owned_and_customer_id_captured() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=f"/{_WS}",
        subscription_id=None,
        arm_client=_arm(workspace=ok(_WORKSPACE_200)),
    )
    assert result.owned == {"log_analytics"}
    assert result.unknown == frozenset()
    ev = result.evidence["log_analytics"]
    assert ev["customer_id"] == "5b02755b-5bf4-430c-9487-45502a2a7e62"
    assert ev["sku"] == "PerGB2018"
    assert ev["retention_in_days"] == 90


def _pricings_ok(*rows: dict) -> object:
    return ok({"value": list(rows)})


def test_cloudposture_standard_owns_cspm() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=None,
        subscription_id=_SUB,
        arm_client=_arm(
            pricings=_pricings_ok(
                {"name": "CloudPosture", "properties": {"pricingTier": "Standard"}},
                {"name": "VirtualMachines", "properties": {"pricingTier": "Free"}},
            )
        ),
    )
    assert result.owned == {"defender_for_cloud_cspm"}
    assert "defender_for_cloud_servers" not in result.owned
    assert result.unknown == {"microsoft_sentinel", "log_analytics"}


def test_virtualmachines_free_does_not_own_servers() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=None,
        subscription_id=_SUB,
        arm_client=_arm(
            pricings=_pricings_ok(
                {"name": "VirtualMachines", "properties": {"pricingTier": "Free"}},
            )
        ),
    )
    assert result.owned == frozenset()
    assert "defender_for_cloud_servers" not in result.unknown


def test_pricings_403_marks_both_unknown() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=f"/{_WS}",
        subscription_id=None,
        arm_client=_arm(
            workspace=ok(_WORKSPACE_200),
            pricings=error(403),
        ),
    )
    assert result.owned == {"log_analytics"}
    assert result.unknown == {"defender_for_cloud_cspm", "defender_for_cloud_servers"}
    assert any("Defender for Cloud" in w for w in result.warnings)


def test_no_scope_everything_unknown() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=None,
        subscription_id=None,
        arm_client=FakeArmClient(),
    )
    assert result.owned == frozenset()
    assert result.unknown == {
        "defender_for_cloud_cspm",
        "defender_for_cloud_servers",
        "log_analytics",
        "microsoft_sentinel",
    }
    assert result.warnings == (
        "No Azure scope supplied; pass --workspace-resource-id or "
        "--subscription-id to assess Sentinel / Defender for Cloud.",
    )


def test_subscription_only_warns_no_workspace() -> None:
    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=None,
        subscription_id=_SUB,
        arm_client=_arm(pricings=error(404)),
    )
    assert (
        "Sentinel and Log Analytics entitlement not assessed: no workspace "
        "resource id was supplied."
    ) in result.warnings


def test_dry_run_owns_sentinel_and_log_analytics_without_arm() -> None:
    class _ExplodingArm:
        def get(self, *_args, **_kwargs) -> dict:
            raise AssertionError("dry_run must not call ARM")

    result = observe_consumption_entitlements(
        _auth(),
        workspace_resource_id=None,
        subscription_id=None,
        arm_client=_ExplodingArm(),  # type: ignore[arg-type]
        dry_run=True,
    )
    assert result.owned == {"microsoft_sentinel", "log_analytics"}
    assert result.unknown == frozenset()
    assert result.warnings == ()
    assert set(result.evidence) == {"microsoft_sentinel", "log_analytics"}


def test_consumption_capabilities_have_no_sku_tokens() -> None:
    caps = {cap.id: cap for cap in load_capabilities()}
    for cap_id in (
        "microsoft_sentinel",
        "log_analytics",
        "defender_for_cloud_cspm",
        "defender_for_cloud_servers",
    ):
        cap = caps[cap_id]
        assert cap.sku_part_numbers == [], cap_id
        assert cap.sku_aliases == [], cap_id
        assert cap.service_plan_names == [], cap_id
        assert cap.service_plan_aliases == [], cap_id
        assert cap.entitlement_kind == "consumption"


def test_merge_consumption_unions_without_unknown() -> None:
    from licenselens.catalog.loader import merge_consumption
    from licenselens.collectors.consumption_entitlements import ConsumptionObservation

    observation = ConsumptionObservation(
        owned=frozenset({"microsoft_sentinel"}),
        unknown=frozenset({"defender_for_cloud_cspm"}),
        evidence={},
        warnings=(),
    )
    merged = merge_consumption(["entra_id_p2"], observation)
    assert merged == ["entra_id_p2", "microsoft_sentinel"]
    assert "defender_for_cloud_cspm" not in merged


def test_demo_owned_capabilities_unchanged_25() -> None:
    from licenselens.engine.runner import run_scan

    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    assert len(result.owned_capabilities) == 25
    assert "microsoft_sentinel" in result.owned_capabilities
    assert "log_analytics" in result.owned_capabilities
    assert "defender_for_cloud_cspm" not in result.owned_capabilities
    assert "defender_for_cloud_servers" not in result.owned_capabilities


def test_demo_subscribed_skus_have_no_microsoft_sentinel() -> None:
    from licenselens.engine.runner import run_scan

    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    parts = [sku.sku_part_number for sku in result.subscribed_skus]
    assert parts == ["SPE_E5"]
    assert "MICROSOFT_SENTINEL" not in parts


def test_discovery_runs_without_sku_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    from licenselens.engine.runner_collect import maybe_discover_workspace

    monkeypatch.setattr(
        "licenselens.collectors.workspace_discover.discover_sentinel_workspaces",
        lambda _auth: [f"/{_WS}"],
    )
    warnings: list[str] = []
    discovered = maybe_discover_workspace(
        auth=_auth(),
        scan_mode="live",
        discover_workspaces=True,
        workspace_resource_id=None,
        warnings=warnings,
    )
    assert discovered == f"/{_WS}"
    assert any("Auto-discovered Sentinel workspace" in w for w in warnings)


def test_live_merge_adds_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    from licenselens.engine.runner import run_scan
    from tests.fake_clients import FakeGraphClient

    arm = _arm(onboarding=ok(_ONBOARDING_200), workspace=ok(_WORKSPACE_200), pricings=error(404))
    monkeypatch.setattr(
        "licenselens.collectors.arm.ArmClient",
        lambda _auth, **_kw: arm,
    )
    graph = FakeGraphClient()
    graph.register_list(
        "/organization", ok({"value": [{"id": "t-3", "displayName": "ObservedCo"}]})
    )
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
                            {
                                "servicePlanName": "AAD_PREMIUM_P2",
                                "provisioningStatus": "Success",
                            }
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
                    {"id": "ss-1", "currentScore": 50.0, "maxScore": 100.0, "controlScores": []}
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
    assert "microsoft_sentinel" in result.owned_capabilities
    assert "log_analytics" in result.owned_capabilities
    assert "defender_for_cloud_servers" not in result.owned_capabilities

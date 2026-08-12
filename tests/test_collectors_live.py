"""MDE, Sentinel, and workspace-discover collector tests using fakes."""

from typing import Any

from licenselens.auth import AuthContext, AuthMode


def _dry_auth() -> AuthContext:
    return AuthContext(mode=AuthMode.DRY_RUN)


# ---------------------------------------------------------------------------
# MDE collector
# ---------------------------------------------------------------------------


def test_mde_summary_odata_count(monkeypatch):
    from tests.fake_clients import FakeMdeClient, ok

    fake = FakeMdeClient()
    fake.register_get(
        "/machines",
        ok({"@odata.count": 42, "value": [{"id": "m1"}]}),
    )
    monkeypatch.setattr(
        "licenselens.collectors.mde.MdeClient", lambda _auth, **kw: fake
    )
    from licenselens.collectors.mde import collect_mde_machine_summary

    result = collect_mde_machine_summary(_dry_auth())
    assert result["onboarded_machines"] == 42
    assert result["count_method"] == "odata_count"


def test_mde_summary_fallback_paged(monkeypatch):
    from tests.fake_clients import FakeMdeClient

    fake = FakeMdeClient()

    def handler(path: str, params) -> dict[str, Any]:
        # First call: $count attempt — return dict WITHOUT @odata.count
        # (so the fallback triggers). Subsequent calls are paged $top/$skip.
        if params is not None and "$count" in str(params):
            return {"value": [{"id": "m1"}]}  # no @odata.count
        if params is not None and "$top" in str(params):
            skip_val = params.get("$skip", "0")
            if str(skip_val) == "0":
                return {"value": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}
            return {"value": []}
        return {"value": []}

    fake.register_get("/machines", handler)
    monkeypatch.setattr(
        "licenselens.collectors.mde.MdeClient", lambda _auth, **kw: fake
    )
    from licenselens.collectors.mde import collect_mde_machine_summary

    result = collect_mde_machine_summary(_dry_auth())
    assert result["onboarded_machines"] == 3
    assert result["count_method"] == "paged_sample"


def test_mde_licensed_units():
    from licenselens.collectors.mde import mde_licensed_units
    from licenselens.models import ServicePlan, SubscribedSku

    sku = SubscribedSku(
        sku_id="e5",
        sku_part_number="SPE_E5",
        capability_status="Enabled",
        prepaid_units=100,
        consumed_units=80,
        service_plans=[
            ServicePlan(
                service_plan_name="DEFENDER_ENDPOINT_P2",
                provisioning_status="Success",
            )
        ],
    )
    assert mde_licensed_units([sku]) == 100


def test_mde_licensed_units_none():
    from licenselens.collectors.mde import mde_licensed_units
    from licenselens.models import ServicePlan, SubscribedSku

    sku = SubscribedSku(
        sku_id="basic",
        sku_part_number="BASIC",
        capability_status="Enabled",
        prepaid_units=10,
        consumed_units=5,
        service_plans=[ServicePlan(service_plan_name="EXCHANGE_S", provisioning_status="Success")],
    )
    assert mde_licensed_units([sku]) is None


# ---------------------------------------------------------------------------
# Sentinel / ARM collectors
# ---------------------------------------------------------------------------


def test_sentinel_alert_rules_empty(monkeypatch):
    from tests.fake_clients import FakeArmClient, ok

    fake = FakeArmClient()
    fake.register_get(
        "subscriptions/",
        ok({"value": []}),
    )
    monkeypatch.setattr(
        "licenselens.collectors.sentinel.ArmClient", lambda _auth, **kw: fake
    )
    from licenselens.collectors.sentinel import collect_sentinel_alert_rules

    result = collect_sentinel_alert_rules(
        _dry_auth(), "/subscriptions/s/rg/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    )
    assert result == []


def test_sentinel_alert_rules(monkeypatch):
    from tests.fake_clients import FakeArmClient, ok

    fake = FakeArmClient()
    fake.register_get(
        "subscriptions/",
        ok(
            {
                "value": [
                    {
                        "id": "r1",
                        "kind": "Scheduled",
                        "properties": {
                            "enabled": True,
                            "displayName": "Find me",
                            "tactics": ["InitialAccess", "Persistence"],
                        },
                    },
                    {
                        "id": "r2",
                        "kind": "Scheduled",
                        "properties": {
                            "enabled": False,
                            "displayName": "Off rule",
                            "tactics": [],
                        },
                    },
                ]
            }
        ),
    )
    monkeypatch.setattr(
        "licenselens.collectors.sentinel.ArmClient", lambda _auth, **kw: fake
    )
    from licenselens.collectors.sentinel import collect_sentinel_alert_rules

    result = collect_sentinel_alert_rules(
        _dry_auth(), "/subscriptions/s/rg/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    )
    assert len(result) == 2
    assert result[0]["id"] == "r1"


def test_sentinel_settings_ueba(monkeypatch):
    from tests.fake_clients import FakeArmClient, ok

    fake = FakeArmClient()
    fake.register_get(
        "subscriptions/",
        ok(
            {
                "value": [
                    {
                        "name": "EntityAnalytics",
                        "kind": "EntityAnalytics",
                        "properties": {"isEnabled": True},
                    }
                ]
            }
        ),
    )
    monkeypatch.setattr(
        "licenselens.collectors.sentinel.ArmClient", lambda _auth, **kw: fake
    )
    from licenselens.collectors.sentinel import collect_sentinel_settings

    result = collect_sentinel_settings(
        _dry_auth(), "/subscriptions/s/rg/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    )
    assert len(result) == 1
    assert result[0]["name"] == "EntityAnalytics"


def test_summarize_alert_rules():
    from licenselens.collectors.sentinel import summarize_alert_rules

    summary = summarize_alert_rules(
        [
            {
                "kind": "Scheduled",
                "properties": {"enabled": True, "displayName": "A", "tactics": ["InitialAccess"]},
            },
            {
                "kind": "Scheduled",
                "properties": {"enabled": True, "displayName": "B", "tactics": ["Persistence"]},
            },
            {
                "kind": "Scheduled",
                "properties": {"enabled": False, "displayName": "C", "tactics": []},
            },
        ]
    )
    assert summary["total_rules"] == 3
    assert summary["enabled_scheduled_or_nrt"] == 2
    assert "InitialAccess" in summary["tactics"]


def test_sentinel_bundle(monkeypatch):
    from tests.fake_clients import FakeArmClient, ok

    fake = FakeArmClient()
    fake.register_get(
        "subscriptions/",
        ok({"value": [{"kind": "Scheduled", "properties": {"enabled": True, "tactics": []}}]}),
    )
    monkeypatch.setattr(
        "licenselens.collectors.sentinel.ArmClient", lambda _auth, **kw: fake
    )
    from licenselens.collectors.sentinel import collect_sentinel_bundle

    bundle = collect_sentinel_bundle(
        _dry_auth(), "/subscriptions/s/rg/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    )
    assert "sentinel_rules" in bundle
    assert bundle["sentinel_rules"]["total_rules"] == 1
    assert "sentinel_ueba" in bundle


# ---------------------------------------------------------------------------
# Workspace discovery
# ---------------------------------------------------------------------------


def test_workspace_discover_no_workspace(monkeypatch):
    from tests.fake_clients import FakeArmClient, ok

    fake_arm = FakeArmClient()
    fake_arm.register_get(
        "/subscriptions/",
        ok({"value": []}),
    )
    monkeypatch.setattr(
        "licenselens.collectors.workspace_discover.ArmClient",
        lambda _auth, **kw: fake_arm,
    )
    monkeypatch.setattr(
        "licenselens.collectors.workspace_discover.list_subscriptions",
        lambda _auth: [],
    )
    from licenselens.collectors.workspace_discover import discover_sentinel_workspaces

    result = discover_sentinel_workspaces(_dry_auth())
    assert result == []


def test_workspace_resource_id_construction():
    from licenselens.collectors.arm import (
        build_workspace_resource_id,
        normalize_workspace_resource_id,
    )

    rid = build_workspace_resource_id(
        subscription_id="sub-id",
        resource_group="rg",
        workspace_name="ws",
    )
    assert "/subscriptions/sub-id" in rid
    assert "Microsoft.OperationalInsights/workspaces/ws" in rid
    assert normalize_workspace_resource_id(rid) == rid
    # Already-normalized
    assert normalize_workspace_resource_id(f" {rid} ") == rid

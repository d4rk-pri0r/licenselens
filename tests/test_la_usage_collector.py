"""WS3-A: la_usage_by_table collector + rules_detail."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from licenselens.auth import AuthContext, AuthMode
from licenselens.collectors.runtime_collect_sentinel import collect_la_usage_runtime
from licenselens.collectors.sentinel import summarize_alert_rules
from licenselens.engine.collection_context import ScanCollectionContext
from licenselens.engine.planner import CollectionContext
from licenselens.errors import GraphError
from tests.fake_clients import FakeArmClient, ok


def _auth() -> AuthContext:
    cred = MagicMock()
    cred.get_token.return_value = MagicMock(token="t")
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=cred)


def _pc() -> CollectionContext:
    return CollectionContext(envelopes={})


def _ctx(*, dry_run: bool = False, workspace: str | None = None) -> ScanCollectionContext:
    return ScanCollectionContext(
        scan_mode="dry_run" if dry_run else "live",
        auth=_auth(),
        client=None,
        skus=[],
        warnings=[],
        workspace_resource_id=workspace,
        extras={},
    )


def test_usage_collected_in_query_mode_dry_run() -> None:
    env = collect_la_usage_runtime(_ctx(dry_run=True), _pc())
    assert env.health.value == "ok"
    assert env.value["mode"] == "query"
    assert "SigninLogs" in env.value["tables"]
    assert env.value["required_surface_incomplete"] is False


def test_unavailable_when_no_workspace() -> None:
    env = collect_la_usage_runtime(_ctx(dry_run=False, workspace=None), _pc())
    assert env.health.value == "unavailable"


def test_falls_back_to_table_list_on_403(monkeypatch: pytest.MonkeyPatch) -> None:
    ws = (
        "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/"
        "resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/lab-ws"
    )
    ctx = _ctx(workspace=ws)
    ctx.extras["_sentinel_extended_cache"] = {
        "sentinel_workspace": {"customer_id": "cccccccc-cccc-cccc-cccc-cccccccccccc"}
    }

    class _Denied:
        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        def __enter__(self) -> _Denied:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def run(self, *_a: object, **_k: object) -> dict:
            raise GraphError("denied", status_code=403)

        def close(self) -> None:
            return None

    arm = FakeArmClient()
    rid = (
        "subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/"
        "resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/lab-ws"
    )
    arm.register_get(
        f"{rid}/tables",
        ok({"value": [{"name": "SigninLogs"}, {"name": "DeviceEvents"}]}),
    )
    monkeypatch.setattr(
        "licenselens.collectors.log_analytics_query.LogAnalyticsQueryClient",
        _Denied,
    )
    monkeypatch.setattr("licenselens.collectors.arm.ArmClient", lambda _auth, **_k: arm)

    env = collect_la_usage_runtime(ctx, _pc())
    assert env.health.value == "ok"
    assert env.value["mode"] == "table_list_only"
    assert env.value["required_surface_incomplete"] is True
    assert "SigninLogs" in env.value["tables"]
    assert env.value["tables"]["SigninLogs"]["rows"] == 0


def test_rules_detail_retains_query_and_kind() -> None:
    summary = summarize_alert_rules(
        [
            {
                "kind": "Scheduled",
                "properties": {
                    "enabled": True,
                    "displayName": "A",
                    "query": "SigninLogs | take 1",
                    "tactics": ["InitialAccess"],
                    "techniques": ["T1078"],
                },
            }
        ]
    )
    assert summary["rules_detail"][0]["query"] == "SigninLogs | take 1"
    assert summary["rules_detail"][0]["kind"] == "Scheduled"
    assert summary["rules_detail_truncated"] is False


def test_rules_detail_truncates_at_500() -> None:
    rules = [
        {
            "kind": "Scheduled",
            "properties": {"enabled": False, "displayName": str(i), "query": "print 1"},
        }
        for i in range(501)
    ]
    summary = summarize_alert_rules(rules)
    assert summary["total_rules"] == 501
    assert len(summary["rules_detail"]) == 500
    assert summary["rules_detail_truncated"] is True

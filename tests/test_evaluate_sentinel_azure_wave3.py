"""Wave 3 todo 24 — Sentinel and selective-Azure checks (final Wave 3 family)."""

from __future__ import annotations

from unittest.mock import MagicMock

from licenselens.auth import AuthContext, AuthMode, build_auth_context
from licenselens.collectors.arm import subscription_id_from_resource_id
from licenselens.collectors.arm_selective import summarize_defender_for_cloud_pricings
from licenselens.collectors.sentinel_extended import (
    DEMO_SENTINEL_AUTOMATION_RULES,
    DEMO_SENTINEL_DATA_CONNECTORS,
    DEMO_SENTINEL_WORKSPACE,
    summarize_automation_rules,
    summarize_data_connectors,
    summarize_log_analytics_workspace,
)
from licenselens.engine.evaluate import (
    evaluate_az_cspm_out_of_scope,
    evaluate_az_defender_plan_enabled,
    evaluate_sen_automation_rules,
    evaluate_sen_data_connectors,
    evaluate_sen_log_analytics_retention,
)
from licenselens.engine.registry import default_registry
from licenselens.engine.runner import run_scan
from licenselens.models import CheckDefinition, FindingStatus, Workload
from tests.fake_clients import FakeArmClient, error, ok


def _check(check_id: str, workload: Workload = Workload.SENTINEL) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=workload)


WID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/demo-rg/providers/Microsoft.OperationalInsights/"
    "workspaces/demo-sentinel"
)


def _fake_auth() -> AuthContext:
    credential = MagicMock()
    credential.get_token.return_value = MagicMock(token="test-token")
    return AuthContext(mode=AuthMode.CLIENT_SECRET, tenant_id="t1", credential=credential)


# ---------------------------------------------------------------------------
# Data connectors
# ---------------------------------------------------------------------------
def test_sen_data_connectors_demo_partial() -> None:
    result = evaluate_sen_data_connectors(
        _check("sen-data-connectors"),
        {"sentinel_data_connectors": DEMO_SENTINEL_DATA_CONNECTORS},
    )
    assert result.status is FindingStatus.PARTIAL


def test_sen_data_connectors_empty_gap() -> None:
    result = evaluate_sen_data_connectors(
        _check("sen-data-connectors"),
        {
            "sentinel_data_connectors": {
                "total_connectors": 0,
                "connected_connectors": 0,
                "connector_kinds": [],
                "key_connectors_connected": [],
                "workspace_resource_id": WID,
            }
        },
    )
    assert result.status is FindingStatus.GAP


def test_sen_data_connectors_ok() -> None:
    result = evaluate_sen_data_connectors(
        _check("sen-data-connectors"),
        {
            "sentinel_data_connectors": {
                "total_connectors": 4,
                "connected_connectors": 4,
                "connector_kinds": ["Office365", "AzureActiveDirectory", "DefenderXDR", "AWS"],
                "key_connectors_connected": ["Office365", "AzureActiveDirectory", "DefenderXDR"],
                "workspace_resource_id": WID,
            }
        },
    )
    assert result.status is FindingStatus.OK


def test_sen_data_connectors_missing_workspace_error() -> None:
    result = evaluate_sen_data_connectors(
        _check("sen-data-connectors"),
        {"sentinel_workspace_missing": True},
    )
    assert result.status is FindingStatus.ERROR


# ---------------------------------------------------------------------------
# Automation rules
# ---------------------------------------------------------------------------
def test_sen_automation_rules_demo_gap() -> None:
    result = evaluate_sen_automation_rules(
        _check("sen-automation-rules"),
        {"sentinel_automation_rules": DEMO_SENTINEL_AUTOMATION_RULES},
    )
    assert result.status is FindingStatus.GAP


def test_sen_automation_rules_ok() -> None:
    result = evaluate_sen_automation_rules(
        _check("sen-automation-rules"),
        {
            "sentinel_automation_rules": {
                "total_automation_rules": 3,
                "enabled_automation_rules": 2,
                "playbook_automation_rules": 2,
                "workspace_resource_id": WID,
            }
        },
    )
    assert result.status is FindingStatus.OK


def test_sen_automation_rules_no_playbook_partial() -> None:
    result = evaluate_sen_automation_rules(
        _check("sen-automation-rules"),
        {
            "sentinel_automation_rules": {
                "total_automation_rules": 2,
                "enabled_automation_rules": 2,
                "playbook_automation_rules": 0,
                "workspace_resource_id": WID,
            }
        },
    )
    assert result.status is FindingStatus.PARTIAL


def test_sen_automation_rules_missing_workspace_error() -> None:
    result = evaluate_sen_automation_rules(
        _check("sen-automation-rules"),
        {"sentinel_workspace_missing": True},
    )
    assert result.status is FindingStatus.ERROR


# ---------------------------------------------------------------------------
# Log Analytics retention
# ---------------------------------------------------------------------------
def test_sen_log_analytics_retention_demo_gap() -> None:
    result = evaluate_sen_log_analytics_retention(
        _check("sen-log-analytics-retention"),
        {"sentinel_workspace": DEMO_SENTINEL_WORKSPACE},
    )
    assert result.status is FindingStatus.GAP


def test_sen_log_analytics_retention_ok() -> None:
    result = evaluate_sen_log_analytics_retention(
        _check("sen-log-analytics-retention"),
        {
            "sentinel_workspace": {
                "retention_in_days": 180,
                "sku": "PerGB2018",
                "workspace_resource_id": WID,
            }
        },
    )
    assert result.status is FindingStatus.OK


def test_sen_log_analytics_retention_partial() -> None:
    result = evaluate_sen_log_analytics_retention(
        _check("sen-log-analytics-retention"),
        {
            "sentinel_workspace": {
                "retention_in_days": 60,
                "sku": "PerGB2018",
                "workspace_resource_id": WID,
            }
        },
    )
    assert result.status is FindingStatus.PARTIAL


def test_sen_log_analytics_retention_unverifiable_error() -> None:
    result = evaluate_sen_log_analytics_retention(
        _check("sen-log-analytics-retention"),
        {
            "sentinel_workspace": {
                "retention_in_days": None,
                "sku": None,
                "workspace_resource_id": WID,
            }
        },
    )
    assert result.status is FindingStatus.ERROR


def test_sen_log_analytics_retention_missing_workspace_error() -> None:
    result = evaluate_sen_log_analytics_retention(
        _check("sen-log-analytics-retention"),
        {"sentinel_workspace_missing": True},
    )
    assert result.status is FindingStatus.ERROR


# ---------------------------------------------------------------------------
# Selective-Azure: Defender for Cloud plan pricing (approved boundary only)
# ---------------------------------------------------------------------------
def test_az_defender_plan_enabled_ok() -> None:
    result = evaluate_az_defender_plan_enabled(
        _check("az-defender-plan-enabled", Workload.AZURE),
        {
            "defender_for_cloud_pricings": {
                "standard_plans": ["VirtualMachines", "CloudPosture"],
                "free_plans": [],
                "total_plans": 2,
                "subscription_id": "sub",
            }
        },
    )
    assert result.status is FindingStatus.OK


def test_az_defender_plan_enabled_gap() -> None:
    result = evaluate_az_defender_plan_enabled(
        _check("az-defender-plan-enabled", Workload.AZURE),
        {
            "defender_for_cloud_pricings": {
                "standard_plans": [],
                "free_plans": ["VirtualMachines"],
                "total_plans": 1,
                "subscription_id": "sub",
            }
        },
    )
    assert result.status is FindingStatus.GAP


def test_az_defender_plan_enabled_denied_error() -> None:
    result = evaluate_az_defender_plan_enabled(
        _check("az-defender-plan-enabled", Workload.AZURE),
        {"defender_for_cloud_pricings_error": "403 Forbidden"},
    )
    assert result.status is FindingStatus.ERROR


# ---------------------------------------------------------------------------
# Explicit unsupported/manual for out-of-scope generic Azure CSPM
# ---------------------------------------------------------------------------
def test_az_cspm_out_of_scope_is_manual_never_ok() -> None:
    result = evaluate_az_cspm_out_of_scope(
        _check("az-cspm-out-of-scope", Workload.AZURE),
        {},
    )
    assert result.status is FindingStatus.SKIPPED
    assert result.evidence.get("manual") is True
    assert result.status is not FindingStatus.OK


# ---------------------------------------------------------------------------
# Boundary: no generic Azure CSPM may slip through
# ---------------------------------------------------------------------------
def test_no_generic_azure_cspm_operations_or_collectors() -> None:
    from licenselens.graph_ops import iter_operations

    banned = (
        "virtualmachines",
        "storageaccounts",
        "sqlservers",
        "networksecuritygroups",
        "microsoft.compute",
        "microsoft.network",
        "microsoft.storage",
        "microsoft.sql",
    )
    arm_ops = [op for op in iter_operations() if op.family.value == "arm"]
    assert arm_ops, "expected selective ARM operations"
    for op in arm_ops:
        lowered = op.path.lower()
        for frag in banned:
            assert frag not in lowered, f"generic Azure surface leaked into {op.operation_id}"


def test_selective_arm_operations_allowlist() -> None:
    from licenselens.graph_ops import iter_operations

    arm_ops = {op.operation_id for op in iter_operations() if op.family.value == "arm"}
    allowed = {
        "arm_sentinel_alert_rules",
        "arm_sentinel_settings",
        "arm_defender_for_cloud_pricings",
    }
    assert arm_ops == allowed


def test_subscription_id_from_resource_id() -> None:
    assert subscription_id_from_resource_id(WID) == "00000000-0000-0000-0000-000000000000"
    assert subscription_id_from_resource_id("not-a-resource-id") is None


def test_summarize_defender_pricings() -> None:
    pricings = [
        {"name": "VirtualMachines", "properties": {"pricingTier": "Standard"}},
        {"name": "SqlServers", "properties": {"pricingTier": "Free"}},
    ]
    summary = summarize_defender_for_cloud_pricings(pricings, "sub")
    assert summary["standard_plans"] == ["VirtualMachines"]
    assert summary["free_plans"] == ["SqlServers"]
    assert summary["total_plans"] == 2
    assert summary["subscription_id"] == "sub"


# ---------------------------------------------------------------------------
# Collector-level coverage through the fake ARM client
# ---------------------------------------------------------------------------
def test_collect_sentinel_extended_bundle_summaries() -> None:
    from licenselens.collectors.sentinel_extended import collect_sentinel_extended_bundle

    fake = FakeArmClient()
    rid = WID.lstrip("/")
    fake.register_get(
        f"{rid}/providers/Microsoft.SecurityInsights/dataConnectors",
        ok({"value": [{"kind": "Office365"}, {"kind": "AzureActiveDirectory"}]}),
    )
    fake.register_get(
        f"{rid}/providers/Microsoft.SecurityInsights/automationRules",
        ok(
            {
                "value": [
                    {"name": "auto", "properties": {"actions": [{"actionType": "RunPlaybook"}]}}
                ]
            }
        ),
    )
    fake.register_get(
        rid,
        ok({"properties": {"retentionInDays": 90}, "sku": {"name": "PerGB2018"}}),
    )
    bundle = collect_sentinel_extended_bundle(_fake_auth(), rid, client=fake)
    assert bundle["sentinel_data_connectors"]["total_connectors"] == 2
    assert bundle["sentinel_automation_rules"]["playbook_automation_rules"] == 1
    assert bundle["sentinel_workspace"]["retention_in_days"] == 90


def test_collect_sentinel_extended_bundle_errors_are_typed() -> None:
    from licenselens.collectors.sentinel_extended import collect_sentinel_extended_bundle

    fake = FakeArmClient()
    rid = WID.lstrip("/")
    fake.register_get(
        f"{rid}/providers/Microsoft.SecurityInsights/dataConnectors",
        error(403, "Forbidden"),
    )
    fake.register_get(
        f"{rid}/providers/Microsoft.SecurityInsights/automationRules",
        error(403, "Forbidden"),
    )
    fake.register_get(rid, error(403, "Forbidden"))
    bundle = collect_sentinel_extended_bundle(_fake_auth(), rid, client=fake)
    assert "sentinel_data_connectors_error" in bundle
    assert "sentinel_automation_rules_error" in bundle
    assert "sentinel_workspace_error" in bundle


# ---------------------------------------------------------------------------
# Entitlement gating + registry + dry-run subset
# ---------------------------------------------------------------------------
def test_entitlement_gating_prevents_irrelevant_findings() -> None:
    from licenselens.engine.loader import load_checks
    from licenselens.engine.runner import _evaluate_check

    checks = {c.id: c for c in load_checks() if c.enabled}
    for check_id in (
        "sen-data-connectors",
        "sen-automation-rules",
        "sen-log-analytics-retention",
        "az-defender-plan-enabled",
        "az-cspm-out-of-scope",
    ):
        check = checks[check_id]
        finding = _evaluate_check(check, set(), {})
        assert finding.status is FindingStatus.NOT_LICENSED, check_id


def test_default_registry_resolves_new_sentinel_azure_checks() -> None:
    registry = default_registry()
    new_ids = {
        "sen-data-connectors",
        "sen-automation-rules",
        "sen-log-analytics-retention",
        "az-defender-plan-enabled",
        "az-cspm-out-of-scope",
    }
    assert new_ids <= set(registry.evaluators)

    modes = {entry.id: entry.evaluation_mode for entry in registry.evaluator_entries}
    assert modes["az-cspm-out-of-scope"].value == "manual"


def test_dry_run_scan_sentinel_azure_subset() -> None:
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    result = run_scan(
        auth,
        dry_run=True,
        workloads=[Workload.SENTINEL, Workload.AZURE],
    )
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["sen-analytics-rule-coverage"].status is FindingStatus.PARTIAL
    assert by_id["sen-ueba-not-enabled"].status is FindingStatus.GAP
    assert by_id["sen-data-connectors"].status in {
        FindingStatus.PARTIAL,
        FindingStatus.GAP,
        FindingStatus.OK,
    }
    assert by_id["sen-automation-rules"].status in {
        FindingStatus.GAP,
        FindingStatus.PARTIAL,
        FindingStatus.OK,
    }
    assert by_id["sen-log-analytics-retention"].status in {
        FindingStatus.GAP,
        FindingStatus.PARTIAL,
        FindingStatus.OK,
    }
    # Selective-Azure checks are entitlement-gated out of the demo tenant.
    assert by_id["az-defender-plan-enabled"].status is FindingStatus.NOT_LICENSED
    assert by_id["az-cspm-out-of-scope"].status is FindingStatus.NOT_LICENSED


# ---------------------------------------------------------------------------
# Summarizer unit coverage (kept isolated from the evaluator thresholds)
# ---------------------------------------------------------------------------
def test_summarize_data_connectors_key_detection() -> None:
    connectors = [
        {"kind": "Office365", "name": "Office 365"},
        {"kind": "AzureActiveDirectory", "name": "Entra ID"},
        {"kind": "AWS", "name": "AWS"},
    ]
    summary = summarize_data_connectors(connectors, WID)
    assert summary["total_connectors"] == 3
    assert set(summary["key_connectors_connected"]) == {"Office365", "AzureActiveDirectory"}


def test_summarize_automation_rules_playbook_detection() -> None:
    rules = [
        {"name": "a", "properties": {"actions": [{"actionType": "RunPlaybook"}]}},
        {"name": "b", "properties": {"actions": [{"actionType": "ModifyProperties"}]}},
    ]
    summary = summarize_automation_rules(rules, WID)
    assert summary["total_automation_rules"] == 2
    assert summary["playbook_automation_rules"] == 1


def test_summarize_log_analytics_workspace_missing_retention() -> None:
    summary = summarize_log_analytics_workspace({"properties": {}}, WID)
    assert summary["retention_in_days"] is None

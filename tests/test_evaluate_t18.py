"""Task 18 SHOULD-ADD checks: Safe Documents, click-through, quarantine, endpoint DLP, PP/PBI."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.exchange import demo_exchange_evidence
from licenselens.collectors.power_data_demo import demo_power_data_evidence
from licenselens.evaluators.power_bi import evaluate_pbi_export_controls
from licenselens.evaluators.power_platform_env import (
    evaluate_pp_dlp_nondefault_environments,
    evaluate_pp_tenant_isolation_allowlist,
)
from licenselens.evaluators.security_suite_dlp import evaluate_pur_endpoint_dlp
from licenselens.evaluators.security_suite_spam import evaluate_mdo_safe_documents
from licenselens.evaluators.security_suite_threat_malware import (
    evaluate_mdo_quarantine_policy,
    evaluate_mdo_safe_links_click_through,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload


def _check(check_id: str, workload: Workload) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=workload)


def _exchange() -> dict[str, Any]:
    return demo_exchange_evidence()


def _set_exchange_prop(
    evidence: dict[str, Any],
    surface: str,
    prop_name: str,
    value: object,
) -> None:
    bundle = evidence["exchange_bundle"]
    item = bundle["adapters"]["exo_threat_policies"]["surfaces"][surface]["items"][0]
    item["properties"][prop_name] = value


def _set_exchange_status(
    evidence: dict[str, Any],
    surface: str,
    status: str,
) -> None:
    bundle = evidence["exchange_bundle"]
    bundle["adapters"]["exo_threat_policies"]["surfaces"][surface]["status"] = status


# --- mdo-safe-documents ---------------------------------------------------------------------


def test_safe_documents_enabled_is_ok() -> None:
    result = evaluate_mdo_safe_documents(
        _check("mdo-safe-documents", Workload.DEFENDER), _exchange()
    )
    assert result.status is FindingStatus.OK


def test_safe_documents_disabled_is_gap() -> None:
    evidence = _exchange()
    _set_exchange_prop(evidence, "atp_global", "EnableSafeDocs", False)
    result = evaluate_mdo_safe_documents(_check("mdo-safe-documents", Workload.DEFENDER), evidence)
    assert result.status is FindingStatus.GAP
    assert result.evidence["enable_safe_docs"] is False


def test_safe_documents_surface_unreadable_is_partial() -> None:
    evidence = _exchange()
    _set_exchange_status(evidence, "atp_global", "denied")
    result = evaluate_mdo_safe_documents(_check("mdo-safe-documents", Workload.DEFENDER), evidence)
    assert result.status is FindingStatus.PARTIAL


# --- mdo-safe-links-click-through -----------------------------------------------------------


def test_click_through_blocked_is_ok() -> None:
    result = evaluate_mdo_safe_links_click_through(
        _check("mdo-safe-links-click-through", Workload.DEFENDER), _exchange()
    )
    assert result.status is FindingStatus.OK


def test_click_through_allowed_is_gap() -> None:
    evidence = _exchange()
    _set_exchange_prop(evidence, "safe_links", "AllowClickThrough", True)
    result = evaluate_mdo_safe_links_click_through(
        _check("mdo-safe-links-click-through", Workload.DEFENDER), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence["allow_click_through"]


def test_click_through_surface_unreadable_is_partial() -> None:
    evidence = _exchange()
    _set_exchange_status(evidence, "safe_links", "denied")
    result = evaluate_mdo_safe_links_click_through(
        _check("mdo-safe-links-click-through", Workload.DEFENDER), evidence
    )
    assert result.status is FindingStatus.PARTIAL


# --- mdo-quarantine-policy ------------------------------------------------------------------


def test_quarantine_limited_access_is_ok() -> None:
    result = evaluate_mdo_quarantine_policy(
        _check("mdo-quarantine-policy", Workload.DEFENDER), _exchange()
    )
    assert result.status is FindingStatus.OK


def test_quarantine_full_access_is_gap() -> None:
    evidence = _exchange()
    _set_exchange_prop(evidence, "quarantine", "EndUserQuarantinePermissionsValue", "FullAccess")
    result = evaluate_mdo_quarantine_policy(
        _check("mdo-quarantine-policy", Workload.DEFENDER), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence["full_access_policies"]


def test_quarantine_short_retention_is_partial() -> None:
    evidence = _exchange()
    _set_exchange_prop(evidence, "quarantine", "RetentionDurationInDays", 15)
    result = evaluate_mdo_quarantine_policy(
        _check("mdo-quarantine-policy", Workload.DEFENDER), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence["retention_days"] == 15


def test_quarantine_surface_unreadable_is_partial() -> None:
    evidence = _exchange()
    _set_exchange_status(evidence, "quarantine", "denied")
    result = evaluate_mdo_quarantine_policy(
        _check("mdo-quarantine-policy", Workload.DEFENDER), evidence
    )
    assert result.status is FindingStatus.PARTIAL


# --- pur-endpoint-dlp -----------------------------------------------------------------------


def test_endpoint_dlp_present_is_ok() -> None:
    result = evaluate_pur_endpoint_dlp(_check("pur-endpoint-dlp", Workload.PURVIEW), _exchange())
    assert result.status is FindingStatus.OK


def test_endpoint_dlp_missing_is_gap() -> None:
    evidence = _exchange()
    bundle = evidence["exchange_bundle"]
    items = bundle["adapters"]["scc_compliance"]["surfaces"]["dlp_policies"]["items"]
    items[:] = [item for item in items if "Devices" not in str(item["properties"].get("Workload"))]
    bundle["adapters"]["scc_compliance"]["surfaces"]["dlp_policies"]["raw_count"] = len(items)
    result = evaluate_pur_endpoint_dlp(_check("pur-endpoint-dlp", Workload.PURVIEW), evidence)
    assert result.status is FindingStatus.GAP
    assert result.evidence["endpoint_dlp_policies"] == []


def test_endpoint_dlp_surface_unreadable_is_partial() -> None:
    evidence = _exchange()
    bundle = evidence["exchange_bundle"]
    bundle["adapters"]["scc_compliance"]["surfaces"]["dlp_policies"]["status"] = "denied"
    result = evaluate_pur_endpoint_dlp(_check("pur-endpoint-dlp", Workload.PURVIEW), evidence)
    assert result.status is FindingStatus.PARTIAL


# --- pp-tenant-isolation-allowlist ----------------------------------------------------------


def _power() -> dict[str, Any]:
    return demo_power_data_evidence()


def _power_surface(evidence: dict[str, Any], adapter: str, surface: str) -> dict[str, Any]:
    return evidence["power_data_bundle"]["adapters"][adapter]["surfaces"][surface]


def test_tenant_isolation_allowlist_present_is_ok() -> None:
    result = evaluate_pp_tenant_isolation_allowlist(
        _check("pp-tenant-isolation-allowlist", Workload.POWER_PLATFORM), _power()
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["allowed_tenants"]


def test_tenant_isolation_off_is_gap() -> None:
    evidence = _power()
    surface = _power_surface(evidence, "pp_isolation", "tenant_isolation")
    surface["items"][0]["properties"]["isolationEnabled"] = False
    surface["items"][0]["enabled"] = False
    result = evaluate_pp_tenant_isolation_allowlist(
        _check("pp-tenant-isolation-allowlist", Workload.POWER_PLATFORM), evidence
    )
    assert result.status is FindingStatus.GAP


def test_tenant_isolation_no_allowlist_is_gap() -> None:
    evidence = _power()
    surface = _power_surface(evidence, "pp_isolation", "tenant_isolation")
    surface["items"][0]["properties"]["allowedTenants"] = []
    result = evaluate_pp_tenant_isolation_allowlist(
        _check("pp-tenant-isolation-allowlist", Workload.POWER_PLATFORM), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence["allowed_tenants"] == []


# --- pp-dlp-nondefault-envs -----------------------------------------------------------------


def test_dlp_nondefault_environments_covered_is_ok() -> None:
    result = evaluate_pp_dlp_nondefault_environments(
        _check("pp-dlp-nondefault-envs", Workload.POWER_PLATFORM), _power()
    )
    assert result.status is FindingStatus.OK


def test_dlp_nondefault_environment_uncovered_is_gap() -> None:
    evidence = _power()
    surface = _power_surface(evidence, "pp_dlp", "dlp_policies")
    surface["items"] = [
        {
            "name": "Default Environment Lockdown",
            "identity": "dlp-default",
            "kind": "custom",
            "enabled": True,
            "properties": {
                "EnvironmentType": "OnlyEnvironments",
                "EnvironmentCount": 1,
                "Environments": ["env-default"],
            },
            "assignments": ["env-default"],
        }
    ]
    surface["raw_count"] = 1
    result = evaluate_pp_dlp_nondefault_environments(
        _check("pp-dlp-nondefault-envs", Workload.POWER_PLATFORM), evidence
    )
    assert result.status is FindingStatus.GAP
    assert "env-prod-finance" in result.evidence["uncovered_nondefault_environments"]


# --- pbi-export-controls --------------------------------------------------------------------


def test_pbi_export_disabled_is_ok() -> None:
    result = evaluate_pbi_export_controls(
        _check("pbi-export-controls", Workload.POWER_BI), _power()
    )
    assert result.status is FindingStatus.OK


def test_pbi_export_enabled_is_gap() -> None:
    evidence = _power()
    surface = _power_surface(evidence, "pbi_tenant", "export_data")
    surface["items"][0]["properties"]["enabled"] = True
    surface["items"][0]["enabled"] = True
    result = evaluate_pbi_export_controls(
        _check("pbi-export-controls", Workload.POWER_BI), evidence
    )
    assert result.status is FindingStatus.GAP


def test_pbi_export_surface_unreadable_is_partial() -> None:
    evidence = _power()
    surface = _power_surface(evidence, "pbi_tenant", "export_data")
    surface["status"] = "unsupported"
    result = evaluate_pbi_export_controls(
        _check("pbi-export-controls", Workload.POWER_BI), evidence
    )
    assert result.status is FindingStatus.PARTIAL


# ---------------------------------------------------------------------------
# Registry / licensing / wiring integration
# ---------------------------------------------------------------------------

_T18_CHECKS = (
    "mdo-safe-documents",
    "mdo-safe-links-click-through",
    "mdo-quarantine-policy",
    "pur-endpoint-dlp",
    "pp-tenant-isolation-allowlist",
    "pp-dlp-nondefault-envs",
    "pbi-export-controls",
)


def test_all_t18_checks_resolve_via_registry_direct() -> None:
    from licenselens.engine.loader import load_checks
    from licenselens.engine.registry import default_registry
    from licenselens.schema_contracts import EvaluationMode

    registry = default_registry()
    ids = {check.id for check in load_checks()}
    assert set(_T18_CHECKS) <= ids
    for check_id in _T18_CHECKS:
        entry = registry.evaluator_for(check_id)
        assert entry.evaluation_mode is EvaluationMode.DIRECT, check_id
        assert entry.input_models in (("exchange_bundle",), ("power_data_bundle",)), check_id
        assert callable(entry.evaluate), check_id


def test_t18_checks_reexported_from_engine_evaluate() -> None:
    from licenselens.engine import evaluate as ev

    for name in (
        "evaluate_mdo_safe_documents",
        "evaluate_mdo_safe_links_click_through",
        "evaluate_mdo_quarantine_policy",
        "evaluate_pur_endpoint_dlp",
        "evaluate_pp_tenant_isolation_allowlist",
        "evaluate_pp_dlp_nondefault_environments",
        "evaluate_pbi_export_controls",
    ):
        assert name in ev.__all__, name
        assert callable(getattr(ev, name)), name


def test_entitlement_gate_prevents_unlicensed_t18_findings() -> None:
    from licenselens.engine.loader import load_checks
    from licenselens.engine.runner import _evaluate_check

    checks = {check.id: check for check in load_checks()}
    for check_id in _T18_CHECKS:
        finding = _evaluate_check(checks[check_id], set(), {})
        assert finding.status is FindingStatus.NOT_LICENSED, check_id


def test_dry_run_scan_renders_all_t18_checks_ok() -> None:
    from licenselens.auth import AuthMode, build_auth_context
    from licenselens.engine.runner import run_scan

    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    result = run_scan(auth, dry_run=True)
    by_id = {finding.check_id: finding for finding in result.findings}
    for check_id in _T18_CHECKS:
        assert check_id in by_id, check_id
        assert by_id[check_id].status is FindingStatus.OK, check_id


def test_t18_scuba_powerplatform_pins_implemented_direct() -> None:
    from licenselens.catalog._reference_coverage import load_coverage_rows
    from licenselens.engine.loader import load_checks
    from licenselens.paths import catalog_dir

    rows, errors = load_coverage_rows(
        catalog_dir() / "coverage" / "scuba-2026-08.yaml",
        {check.id for check in load_checks()},
    )
    assert not errors
    by_id = {row.policy_id: row for row in rows}
    assert by_id["MS.POWERPLATFORM.2.2v1"].disposition.value == "implemented_direct"
    assert by_id["MS.POWERPLATFORM.2.2v1"].local_check_ids == ("pp-dlp-nondefault-envs",)
    assert by_id["MS.POWERPLATFORM.3.2v1"].disposition.value == "implemented_direct"
    assert by_id["MS.POWERPLATFORM.3.2v1"].local_check_ids == ("pp-tenant-isolation-allowlist",)


def test_t18_power_platform_admin_rest_scopes_documented() -> None:
    from licenselens.auth import REQUIRED_POWERBI_APP_PERMISSIONS

    assert "Tenant.Read.All" in REQUIRED_POWERBI_APP_PERMISSIONS

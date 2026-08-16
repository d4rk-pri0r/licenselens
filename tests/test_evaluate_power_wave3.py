"""Wave 3 Power Platform and Power BI evaluator coverage (Todo 21)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.power_data_demo import demo_power_data_evidence
from licenselens.collectors.power_data_models import (
    COVERAGE_SURFACE_MAP,
    MANUAL_PORTAL_POLICY_IDS,
    PowerDataBundle,
    SurfaceStatus,
)
from licenselens.collectors.power_data_normalize import coverage_evidence_for_bundle
from licenselens.engine.loader import load_checks
from licenselens.engine.runner import _evaluate_check
from licenselens.evaluators.power_bi import (
    evaluate_pbi_external_invite_disabled,
    evaluate_pbi_guest_access_disabled,
    evaluate_pbi_publish_to_web_disabled,
    evaluate_pbi_python_r_visuals_disabled,
    evaluate_pbi_resource_key_auth_blocked,
    evaluate_pbi_sensitivity_labels_enabled,
    evaluate_pbi_sp_api_restricted,
    evaluate_pbi_sp_profiles_disabled,
)
from licenselens.evaluators.power_platform_env import (
    evaluate_pp_dlp_all_environments,
    evaluate_pp_tenant_isolation_enabled,
)
from licenselens.evaluators.power_platform_tenant import (
    evaluate_pp_env_creation_admin_only,
    evaluate_pp_pages_creation_admin_only,
    evaluate_pp_share_with_everyone_disabled,
    evaluate_pp_trial_creation_admin_only,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload

_POWER_CHECKS = (
    "pp-env-creation-admin-only",
    "pp-trial-creation-admin-only",
    "pp-dlp-all-environments",
    "pp-dlp-nondefault-envs",
    "pp-tenant-isolation-enabled",
    "pp-tenant-isolation-allowlist",
    "pp-pages-creation-admin-only",
    "pp-share-with-everyone-disabled",
    "pbi-publish-to-web-disabled",
    "pbi-guest-access-disabled",
    "pbi-external-invite-disabled",
    "pbi-sp-api-restricted",
    "pbi-sp-profiles-disabled",
    "pbi-resource-key-auth-blocked",
    "pbi-python-r-visuals-disabled",
    "pbi-sensitivity-labels-enabled",
    "pbi-export-controls",
)


def _check(check_id: str) -> CheckDefinition:
    workload = Workload.POWER_PLATFORM if check_id.startswith("pp-") else Workload.POWER_BI
    return CheckDefinition(id=check_id, title=check_id, workload=workload)


def _demo() -> dict[str, Any]:
    return demo_power_data_evidence()


def _surface(bundle: dict[str, Any], adapter: str, surface: str) -> dict[str, Any]:
    return bundle["power_data_bundle"]["adapters"][adapter]["surfaces"][surface]


def _set_dlp_items(evidence: dict[str, Any], items: list[dict[str, Any]]) -> None:
    _surface(evidence, "pp_dlp", "dlp_policies")["items"] = items
    _surface(evidence, "pp_dlp", "dlp_policies")["raw_count"] = len(items)


def test_demo_power_matrix_all_direct_checks_ok() -> None:
    evidence = _demo()
    assert (
        evaluate_pp_env_creation_admin_only(_check("pp-env-creation-admin-only"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pp_trial_creation_admin_only(
            _check("pp-trial-creation-admin-only"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pp_dlp_all_environments(_check("pp-dlp-all-environments"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pp_tenant_isolation_enabled(_check("pp-tenant-isolation-enabled"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pp_pages_creation_admin_only(
            _check("pp-pages-creation-admin-only"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pp_share_with_everyone_disabled(
            _check("pp-share-with-everyone-disabled"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pbi_publish_to_web_disabled(_check("pbi-publish-to-web-disabled"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pbi_guest_access_disabled(_check("pbi-guest-access-disabled"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pbi_external_invite_disabled(
            _check("pbi-external-invite-disabled"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pbi_sp_api_restricted(_check("pbi-sp-api-restricted"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pbi_sp_profiles_disabled(_check("pbi-sp-profiles-disabled"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pbi_resource_key_auth_blocked(
            _check("pbi-resource-key-auth-blocked"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pbi_python_r_visuals_disabled(
            _check("pbi-python-r-visuals-disabled"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pbi_sensitivity_labels_enabled(
            _check("pbi-sensitivity-labels-enabled"), evidence
        ).status
        is FindingStatus.OK
    )


def test_unconfigured_default_environment_is_not_hidden_by_compliant_aggregate() -> None:
    evidence = _demo()
    # Keep only the "All Non-Default" policy, which excludes the default environment.
    _set_dlp_items(
        evidence,
        [
            {
                "name": "All Non-Default",
                "identity": "dlp-all-others",
                "kind": "custom",
                "enabled": True,
                "properties": {
                    "EnvironmentType": "ExceptEnvironments",
                    "EnvironmentCount": 1,
                    "Environments": ["env-default"],
                },
                "assignments": ["env-default"],
            }
        ],
    )
    result = evaluate_pp_dlp_all_environments(_check("pp-dlp-all-environments"), evidence)
    assert result.status is FindingStatus.GAP
    assert "env-default" in result.evidence["uncovered_environments"]


def test_dlp_no_policies_is_gap_not_partial() -> None:
    evidence = _demo()
    _set_dlp_items(evidence, [])
    result = evaluate_pp_dlp_all_environments(_check("pp-dlp-all-environments"), evidence)
    assert result.status is FindingStatus.GAP
    assert result.evidence["uncovered_environments"] == sorted(
        {"env-default", "env-prod-finance", "env-sandbox-nodv"}
    )


def test_dlp_unreadable_environment_inventory_is_partial() -> None:
    evidence = _demo()
    _surface(evidence, "pp_environments", "environments")["status"] = "denied"
    result = evaluate_pp_dlp_all_environments(_check("pp-dlp-all-environments"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK


def test_tenant_isolation_disabled_is_gap() -> None:
    evidence = _demo()
    surface = _surface(evidence, "pp_isolation", "tenant_isolation")
    surface["items"][0]["properties"]["isolationEnabled"] = False
    surface["items"][0]["enabled"] = False
    result = evaluate_pp_tenant_isolation_enabled(_check("pp-tenant-isolation-enabled"), evidence)
    assert result.status is FindingStatus.GAP


def test_pbi_sp_api_unrestricted_is_gap_without_guessed_allowlist() -> None:
    evidence = _demo()
    surface = _surface(evidence, "pbi_tenant", "service_principal_api")
    surface["items"][0]["properties"]["enabled"] = True
    surface["items"][0]["properties"].pop("securityGroups", None)
    result = evaluate_pbi_sp_api_restricted(_check("pbi-sp-api-restricted"), evidence)
    assert result.status is FindingStatus.GAP
    # The evaluator never fabricates a default security-group allowlist.
    assert result.evidence["security_groups"] == []


def test_pbi_sp_api_disabled_is_ok() -> None:
    evidence = _demo()
    surface = _surface(evidence, "pbi_tenant", "service_principal_api")
    surface["items"][0]["properties"]["enabled"] = False
    surface["items"][0]["enabled"] = False
    result = evaluate_pbi_sp_api_restricted(_check("pbi-sp-api-restricted"), evidence)
    assert result.status is FindingStatus.OK


def test_pbi_module_drift_is_partial_not_false_gap() -> None:
    from licenselens.collectors.power_data_fixtures import DEMO_PBI_MODULE_DRIFT_PAYLOAD
    from licenselens.collectors.power_data_normalize import normalize_adapter_payload

    bundle = PowerDataBundle(
        adapters={
            "pbi_tenant": normalize_adapter_payload(
                DEMO_PBI_MODULE_DRIFT_PAYLOAD, adapter="pbi_tenant"
            )
        }
    )
    evidence = {"power_data_bundle": bundle.model_dump(mode="json")}
    result = evaluate_pbi_publish_to_web_disabled(_check("pbi-publish-to-web-disabled"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP
    assert result.status is not FindingStatus.OK


def test_manual_and_portal_only_rows_are_not_false_gaps() -> None:
    # Coverage manifest dispositions stay manual for the CSP (4.1) row.
    from licenselens.catalog._reference_coverage import load_coverage_rows

    rows, errors = load_coverage_rows(
        __import__("licenselens.paths", fromlist=["catalog_dir"]).catalog_dir()
        / "coverage"
        / "scuba-2026-08.yaml",
        {check.id for check in load_checks()},
    )
    assert not errors
    by_id = {row.policy_id: row for row in rows}
    assert by_id["MS.POWERPLATFORM.4.1v1"].disposition.value == "manual"
    assert by_id["MS.POWERPLATFORM.4.1v1"].local_check_ids == ()
    assert by_id["MS.POWERPLATFORM.2.2v1"].disposition.value == "implemented_direct"
    assert by_id["MS.POWERPLATFORM.3.2v1"].disposition.value == "implemented_direct"

    # Collector evidence marks the portal-only rows unsupported, never a fabricated pass.
    adapters = {
        name: __import__(
            "licenselens.collectors.power_data_normalize",
            fromlist=["normalize_adapter_payload"],
        ).normalize_adapter_payload(payload, adapter=name)
        for name, payload in _demo_adapters().items()
    }
    bundle = PowerDataBundle(adapters=adapters)
    evidence = {row.policy_id: row for row in coverage_evidence_for_bundle(bundle)}
    for policy_id in MANUAL_PORTAL_POLICY_IDS:
        row = evidence[policy_id]
        assert row.status is SurfaceStatus.UNSUPPORTED
        assert row.portal_only is True


def test_all_power_checks_resolve_via_registry_direct() -> None:
    from licenselens.engine.registry import default_registry
    from licenselens.schema_contracts import EvaluationMode

    registry = default_registry()
    power_ids = {check.id for check in load_checks() if check.id in set(_POWER_CHECKS)}
    assert power_ids == set(_POWER_CHECKS)
    for check_id in power_ids:
        entry = registry.evaluator_for(check_id)
        assert entry.evaluation_mode is EvaluationMode.DIRECT
        assert entry.input_models == ("power_data_bundle",)


def test_entitlement_gate_prevents_irrelevant_findings() -> None:
    check = next(check for check in load_checks() if check.id == "pbi-guest-access-disabled")
    # Not owning the capability yields not_licensed, never a fabricated gap.
    finding = _evaluate_check(check, set(), _demo())
    assert finding.status is FindingStatus.NOT_LICENSED


def test_profile_applicability_partitions_pp_and_pbi() -> None:
    from licenselens.engine.profiles import compose_profile

    pp = compose_profile("power-platform")
    pbi = compose_profile("power-bi")
    pp_ids = set(pp.selected_check_ids)
    pbi_ids = set(pbi.selected_check_ids)
    assert {"pp-env-creation-admin-only", "pp-dlp-all-environments"} <= pp_ids
    assert {"pbi-publish-to-web-disabled", "pbi-sensitivity-labels-enabled"} <= pbi_ids
    assert not (pp_ids & pbi_ids)


def test_demo_evidence_is_deep_copied_between_builds() -> None:
    first = _demo()
    second = _demo()
    _set_dlp_items(first, [])
    assert first["power_data_bundle"] != second["power_data_bundle"]
    result = evaluate_pp_dlp_all_environments(_check("pp-dlp-all-environments"), second)
    assert result.status is FindingStatus.OK


def _demo_adapters() -> dict[str, dict[str, Any]]:
    from licenselens.collectors.power_data_fixtures import DEMO_FIXTURES

    return dict(DEMO_FIXTURES)


def test_coverage_surface_map_covers_all_power_rows() -> None:
    assert set(COVERAGE_SURFACE_MAP) == {
        "MS.POWERPLATFORM.1.1v1",
        "MS.POWERPLATFORM.1.2v1",
        "MS.POWERPLATFORM.2.1v1",
        "MS.POWERPLATFORM.2.2v1",
        "MS.POWERPLATFORM.3.1v1",
        "MS.POWERPLATFORM.3.2v1",
        "MS.POWERPLATFORM.4.1v1",
        "MS.POWERPLATFORM.5.1v1",
        "MS.POWERPLATFORM.6.1v1",
        "MS.POWERBI.1.1v1",
        "MS.POWERBI.2.1v1",
        "MS.POWERBI.3.1v1",
        "MS.POWERBI.4.1v1",
        "MS.POWERBI.4.2v1",
        "MS.POWERBI.5.1v1",
        "MS.POWERBI.6.1v1",
        "MS.POWERBI.7.1v1",
    }

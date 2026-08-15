"""Power Platform environment aggregation and tenant-isolation evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.power_data_models import (
    PP_DLP_ADAPTER,
    PP_ENVIRONMENTS_ADAPTER,
    PP_ISOLATION_ADAPTER,
    PolicyItem,
    PowerDataBundle,
)
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.power_lib import (
    direct_meta,
    items,
    power_bundle,
    prop_bool_optional,
    prop_str,
    unavailable,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def _env_keys(bundle: PowerDataBundle | None, adapter: str, name: str) -> list[str]:
    keys: list[str] = []
    for item in items(bundle, adapter, name):
        key = item.identity or item.name
        if key:
            keys.append(str(key))
    return keys


def _policy_coverage(policy: PolicyItem, all_env_keys: set[str]) -> set[str]:
    env_type = prop_str(policy, "EnvironmentType").strip().lower()
    env_list = {str(name) for name in policy.assignments if name}
    raw_list = policy.properties.get("Environments")
    if isinstance(raw_list, list):
        env_list |= {str(name) for name in raw_list if name}
    if env_type == "allenvironments":
        return set(all_env_keys)
    if env_type == "onlyenvironments":
        return env_list & all_env_keys
    if env_type == "exceptenvironments":
        return all_env_keys - env_list
    return env_list & all_env_keys


def evaluate_pp_dlp_all_environments(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = power_bundle(evidence)
    if not usable(bundle, PP_ENVIRONMENTS_ADAPTER, "environments"):
        return unavailable(
            "Environment inventory could not be read; DLP coverage is unresolved.",
            adapter=PP_ENVIRONMENTS_ADAPTER,
            surface_name="environments",
            customer_summary="We could not confirm whether every environment has a DLP policy.",
        )
    env_keys = _env_keys(bundle, PP_ENVIRONMENTS_ADAPTER, "environments")
    if not env_keys:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No environments were returned; DLP coverage is unresolved.",
            evidence={"environment_count": 0},
            customer_summary="Confirm DLP policies cover every environment.",
            confidence=Confidence.MEDIUM,
            limitations=["No Power Platform environments were collected."],
        )
    all_env_keys = set(env_keys)
    if not usable(bundle, PP_DLP_ADAPTER, "dlp_policies"):
        return unavailable(
            "DLP policies could not be read; coverage is unresolved.",
            adapter=PP_DLP_ADAPTER,
            surface_name="dlp_policies",
            customer_summary="We could not confirm whether every environment has a DLP policy.",
        )
    policies = items(bundle, PP_DLP_ADAPTER, "dlp_policies")
    covered: set[str] = set()
    for policy in policies:
        covered |= _policy_coverage(policy, all_env_keys)
    uncovered = sorted(all_env_keys - covered)
    evidence_out = {
        "environment_count": len(all_env_keys),
        "dlp_policy_count": len(policies),
        "covered_environments": sorted(covered),
        "uncovered_environments": uncovered,
    }
    if not policies:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No DLP policies are configured; no environment is protected.",
            evidence=evidence_out,
            customer_summary=(
                "No DLP policy exists, so every environment is unprotected. Create one "
                "and cover every environment."
            ),
            **direct_meta(),
        )
    if uncovered:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"DLP does not cover environments: {', '.join(uncovered)}.",
            evidence=evidence_out,
            customer_summary=(
                "Some environments have no DLP policy. Assign a policy to every "
                "uncovered environment."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Every Power Platform environment is covered by a DLP policy.",
        evidence=evidence_out,
        customer_summary="Every environment has a DLP policy.",
        **direct_meta(),
    )


def evaluate_pp_tenant_isolation_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = power_bundle(evidence)
    if not usable(bundle, PP_ISOLATION_ADAPTER, "tenant_isolation"):
        return unavailable(
            "Tenant isolation policy could not be read; treated as unresolved.",
            adapter=PP_ISOLATION_ADAPTER,
            surface_name="tenant_isolation",
            customer_summary="We could not confirm whether tenant isolation is enabled.",
        )
    found = items(bundle, PP_ISOLATION_ADAPTER, "tenant_isolation")
    if not found:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Tenant isolation policy was returned without a conclusive value.",
            evidence={"surface": "tenant_isolation"},
            customer_summary="Confirm tenant isolation in the Power Platform admin center.",
            confidence=Confidence.MEDIUM,
            limitations=["Tenant isolation state was not reported."],
        )
    item = found[0]
    enabled = prop_bool_optional(item, "isolationEnabled")
    if enabled is None:
        enabled = item.enabled
    evidence_out = {"surface": "tenant_isolation", "isolation_enabled": enabled}
    if enabled is True:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Power Platform tenant isolation is enabled.",
            evidence=evidence_out,
            customer_summary="Tenant isolation is enabled.",
            **direct_meta(),
        )
    if enabled is False:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Power Platform tenant isolation is not enforced.",
            evidence=evidence_out,
            customer_summary="Enable tenant isolation to block cross-tenant connections.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="Tenant isolation state could not be determined.",
        evidence=evidence_out,
        customer_summary="Confirm tenant isolation in the Power Platform admin center.",
        confidence=Confidence.MEDIUM,
        limitations=["Tenant isolation state was not reported."],
    )


__all__ = [
    "evaluate_pp_dlp_all_environments",
    "evaluate_pp_tenant_isolation_enabled",
]

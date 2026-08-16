"""Power BI tenant-security-setting evaluators (SCuBA MS.POWERBI.* rows)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.power_data_models import PolicyItem
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.power_lib import (
    PBI_TENANT_ADAPTER,
    direct_meta,
    items,
    pbi_bool_result,
    power_bundle,
    prop_bool_optional,
    unavailable,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_pbi_publish_to_web_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return pbi_bool_result(
        bundle=power_bundle(evidence),
        surface_name="publish_to_web",
        expect=False,
        ok_summary="Power BI publish to web is disabled.",
        gap_summary="Power BI publish to web is enabled.",
        customer_ok="Publish to web is off.",
        customer_gap="Turn off publish to web.",
    )


def evaluate_pbi_guest_access_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return pbi_bool_result(
        bundle=power_bundle(evidence),
        surface_name="guest_access",
        expect=False,
        ok_summary="Power BI guest user access is disabled.",
        gap_summary="Power BI guest user access is enabled.",
        customer_ok="Guest access is off.",
        customer_gap="Turn off guest user access.",
    )


def evaluate_pbi_external_invite_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return pbi_bool_result(
        bundle=power_bundle(evidence),
        surface_name="external_invite",
        expect=False,
        ok_summary="External invitations to Power BI content are disabled.",
        gap_summary="Users can invite external people to Power BI content.",
        customer_ok="External invitations are off.",
        customer_gap="Turn off external invitations.",
    )


def _security_groups(item: PolicyItem) -> list[str]:
    raw = item.properties.get("securityGroups")
    if not isinstance(raw, list):
        return []
    return [str(group) for group in raw if group]


def evaluate_pbi_sp_api_restricted(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = power_bundle(evidence)
    if not usable(bundle, PBI_TENANT_ADAPTER, "service_principal_api"):
        return unavailable(
            "Service principal API setting could not be read; treated as unresolved.",
            adapter=PBI_TENANT_ADAPTER,
            surface_name="service_principal_api",
            customer_summary=(
                "We could not confirm whether service principal API access is restricted."
            ),
        )
    found = items(bundle, PBI_TENANT_ADAPTER, "service_principal_api")
    if not found:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Service principal API setting was returned without a value.",
            evidence={"surface": "service_principal_api"},
            customer_summary="Confirm service principal API access in the Power BI admin portal.",
            confidence=Confidence.MEDIUM,
            limitations=["Service principal API state was not reported."],
        )
    item = found[0]
    enabled = prop_bool_optional(item, "enabled")
    if enabled is None:
        enabled = item.enabled
    groups = _security_groups(item)
    evidence_out = {
        "surface": "service_principal_api",
        "enabled": enabled,
        "security_groups": groups,
    }
    if enabled is False:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Service principals cannot use Power BI / Fabric APIs.",
            evidence=evidence_out,
            customer_summary="Service principal API access is disabled.",
            **direct_meta(),
        )
    if enabled is True and groups:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Service principal API access is limited to specific security groups.",
            evidence=evidence_out,
            customer_summary="Service principal API access is restricted to allowed groups.",
            **direct_meta(),
        )
    if enabled is True:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Service principals can use Power BI / Fabric APIs for the entire organization."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Restrict service principal API access to specific security groups or disable it."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="Service principal API state could not be determined.",
        evidence=evidence_out,
        customer_summary="Confirm service principal API access in the Power BI admin portal.",
        confidence=Confidence.MEDIUM,
        limitations=["Service principal API state was not reported."],
    )


def evaluate_pbi_sp_profiles_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return pbi_bool_result(
        bundle=power_bundle(evidence),
        surface_name="service_principal_profiles",
        expect=False,
        ok_summary="Service principal Power BI profile creation is disabled.",
        gap_summary="Service principals can create and use Power BI profiles.",
        customer_ok="Service principal profiles are off.",
        customer_gap="Turn off service principal profiles.",
    )


def evaluate_pbi_resource_key_auth_blocked(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return pbi_bool_result(
        bundle=power_bundle(evidence),
        surface_name="resource_key_auth",
        expect=True,
        ok_summary="Power BI resource key authentication is blocked.",
        gap_summary="Power BI resource key authentication is not blocked.",
        customer_ok="Resource key authentication is blocked.",
        customer_gap="Block resource key authentication.",
    )


def evaluate_pbi_python_r_visuals_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return pbi_bool_result(
        bundle=power_bundle(evidence),
        surface_name="python_r_visuals",
        expect=False,
        ok_summary="Python and R visuals are disabled.",
        gap_summary="Python and R visuals are enabled.",
        customer_ok="Python and R visuals are off.",
        customer_gap="Turn off Python and R visuals.",
    )


def evaluate_pbi_sensitivity_labels_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return pbi_bool_result(
        bundle=power_bundle(evidence),
        surface_name="sensitivity_labels",
        expect=True,
        ok_summary="Power BI sensitivity labels are enabled.",
        gap_summary="Power BI sensitivity labels are not enabled.",
        customer_ok="Sensitivity labels are applied to Power BI content.",
        customer_gap="Turn on sensitivity labels for Power BI content.",
    )


def evaluate_pbi_export_controls(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return pbi_bool_result(
        bundle=power_bundle(evidence),
        surface_name="export_data",
        expect=False,
        ok_summary="Power BI data export is disabled.",
        gap_summary="Power BI data export is enabled for the organization.",
        customer_ok="Data export from Power BI is off.",
        customer_gap="Turn off Power BI data export.",
    )


def evaluate_pbi_premium_capacity_governance(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = evidence.get("pbi_capacity_bundle")
    if not isinstance(bundle, dict):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Power BI Premium capacity evidence was not collected; governance "
                "could not be verified automatically."
            ),
            evidence={"pbi_capacity_bundle": None},
            customer_summary=(
                "We could not confirm Premium capacity governance automatically. "
                "Review capacity admins and workspace mapping in the Power BI admin portal."
            ),
            confidence=Confidence.LOW,
            limitations=["Power BI admin REST read unavailable — verify in the admin portal."],
        )

    capacity_count = int(bundle.get("capacity_count") or 0)
    admin_count = int(bundle.get("total_admin_count") or 0)
    if capacity_count == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No Premium/Fabric capacities were returned. The tenant may rely on "
                "Premium-per-user licensing instead; entitlement use is unconfirmed."
            ),
            evidence=dict(bundle, direct=True),
            customer_summary=(
                "No Premium capacities are in use (or the API could not see them). "
                "Confirm whether Premium-per-user seats are assigned intentionally."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["powerbi.admin.rest.capacities"],
            limitations=[
                "Premium-per-user (PPU) seat assignment is not readable via the "
                "capacities API; confirm in the admin portal.",
            ],
        )

    return Evaluation(
        status=FindingStatus.OK,
        summary=(
            f"{capacity_count} Premium/Fabric capacit(y/ies) in use with "
            f"{admin_count} capacity admin assignment(s)."
        ),
        evidence=dict(bundle, direct=True),
        customer_summary=(
            "Premium capacity governance is active. Keep the capacity-admin list "
            "small and workspace-to-capacity mapping documented."
        ),
        confidence=Confidence.HIGH,
        data_sources=["powerbi.admin.rest.capacities", "powerbi.admin.rest.tenantsettings"],
        limitations=[
            "Workspace-to-capacity mapping and per-user entitlement provenance "
            "still require a portal review.",
        ],
    )


__all__ = [
    "evaluate_pbi_export_controls",
    "evaluate_pbi_external_invite_disabled",
    "evaluate_pbi_guest_access_disabled",
    "evaluate_pbi_premium_capacity_governance",
    "evaluate_pbi_publish_to_web_disabled",
    "evaluate_pbi_python_r_visuals_disabled",
    "evaluate_pbi_resource_key_auth_blocked",
    "evaluate_pbi_sensitivity_labels_enabled",
    "evaluate_pbi_sp_api_restricted",
    "evaluate_pbi_sp_profiles_disabled",
]

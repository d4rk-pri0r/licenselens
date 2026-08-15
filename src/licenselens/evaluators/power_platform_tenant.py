"""Power Platform tenant-setting evaluators (environment, pages, share-with-everyone)."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.power_lib import power_bundle, tenant_bool_result
from licenselens.models import CheckDefinition


def evaluate_pp_env_creation_admin_only(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return tenant_bool_result(
        bundle=power_bundle(evidence),
        surface_name="environment_creation",
        prop_name="disableEnvironmentCreationByNonAdminUsers",
        expect=True,
        ok_summary="Environment creation is restricted to admins.",
        gap_summary="Non-admin users can create Power Platform environments.",
        customer_ok="Environment creation is admin-only.",
        customer_gap="Restrict environment creation to admins.",
    )


def evaluate_pp_trial_creation_admin_only(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return tenant_bool_result(
        bundle=power_bundle(evidence),
        surface_name="environment_creation",
        prop_name="disableTrialEnvironmentCreationByNonAdminUsers",
        expect=True,
        ok_summary="Trial environment creation is restricted to admins.",
        gap_summary="Non-admin users can create Power Platform trial environments.",
        customer_ok="Trial environment creation is admin-only.",
        customer_gap="Restrict trial environment creation to admins.",
    )


def evaluate_pp_pages_creation_admin_only(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return tenant_bool_result(
        bundle=power_bundle(evidence),
        surface_name="power_pages",
        prop_name="disablePortalsCreationByNonAdminUsers",
        expect=True,
        ok_summary="Power Pages creation is restricted to admins.",
        gap_summary="Non-admin users can create Power Pages sites.",
        customer_ok="Power Pages creation is admin-only.",
        customer_gap="Restrict Power Pages creation to admins.",
    )


def evaluate_pp_share_with_everyone_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return tenant_bool_result(
        bundle=power_bundle(evidence),
        surface_name="share_with_everyone",
        prop_name="disableShareWithEveryone",
        expect=True,
        ok_summary="Sharing Power Apps with everyone is disabled.",
        gap_summary="Power Apps can be shared with everyone in the organization.",
        customer_ok="Share-with-everyone is disabled.",
        customer_gap="Disable share-with-everyone for Power Apps.",
    )


__all__ = [
    "evaluate_pp_env_creation_admin_only",
    "evaluate_pp_pages_creation_admin_only",
    "evaluate_pp_share_with_everyone_disabled",
    "evaluate_pp_trial_creation_admin_only",
]

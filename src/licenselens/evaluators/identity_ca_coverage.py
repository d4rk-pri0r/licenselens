"""Conditional Access coverage evaluators (legacy, MFA, devices, device code)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors import conditional_access as ca
from licenselens.collectors.privileged_roles import HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.identity_ca_lib import (
    break_glass_principal_ids,
    ca_coverage_result,
    role_targeted_result,
)
from licenselens.models import CheckDefinition


def _policies(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return list(evidence.get("ca_policies") or [])


def evaluate_ca_legacy_auth_block(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return ca_coverage_result(
        label="Legacy authentication block",
        policies=_policies(evidence),
        predicate=ca.is_legacy_auth_block,
        justified=break_glass_principal_ids(evidence),
        ok_summary="Enforced Conditional Access blocks legacy authentication clients.",
        ok_customer=("Outdated sign-in methods that skip modern security checks are blocked."),
        gap_summary="No enforced Conditional Access policy blocks legacy authentication.",
        gap_customer=("Outdated sign-in methods may still work without multi-factor checks."),
    )


def evaluate_ca_mfa_all_users(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return ca_coverage_result(
        label="MFA for all users",
        policies=_policies(evidence),
        predicate=ca.requires_mfa,
        justified=break_glass_principal_ids(evidence),
        ok_summary="Enforced Conditional Access requires MFA for all users.",
        ok_customer="Everyone must use multi-factor authentication when signing in.",
        gap_summary="No enforced all-user MFA Conditional Access policy was found.",
        gap_customer="Not everyone is required to use multi-factor authentication.",
    )


def evaluate_ca_phishing_resistant_all(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return ca_coverage_result(
        label="Phishing-resistant MFA for all users",
        policies=_policies(evidence),
        predicate=ca.requires_phishing_resistant,
        justified=break_glass_principal_ids(evidence),
        ok_summary="Enforced Conditional Access requires phishing-resistant MFA for all users.",
        ok_customer=("Sign-in requires strong phishing-resistant methods such as FIDO2 or CBA."),
        gap_summary="No enforced all-user phishing-resistant MFA policy was found.",
        gap_customer=(
            "Users can still sign in with weaker multi-factor methods that phishing can defeat."
        ),
    )


def evaluate_ca_phishing_resistant_privileged(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return role_targeted_result(
        label="Phishing-resistant MFA for privileged roles",
        policies=_policies(evidence),
        predicate=ca.requires_phishing_resistant,
        role_ids=set(HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS),
        justified=break_glass_principal_ids(evidence),
        ok_summary=(
            "Enforced Conditional Access requires phishing-resistant MFA for "
            "highly privileged roles (or all users)."
        ),
        ok_customer="Powerful admin roles require strong phishing-resistant sign-in methods.",
        gap_summary=("No enforced phishing-resistant MFA policy covers highly privileged roles."),
        gap_customer=("Admin accounts may still sign in with weaker multi-factor methods."),
    )


def evaluate_ca_managed_devices(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return ca_coverage_result(
        label="Managed device required",
        policies=_policies(evidence),
        predicate=ca.requires_managed_device,
        justified=break_glass_principal_ids(evidence),
        ok_summary="Enforced Conditional Access requires a managed device for access.",
        ok_customer="People must use company-managed devices to reach work apps.",
        gap_summary="No enforced managed-device Conditional Access policy was found.",
        gap_customer="Users may access work apps from unmanaged personal devices.",
    )


def evaluate_ca_mfa_registration_managed(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check

    def _pred(policy: dict[str, Any]) -> bool:
        return ca.targets_register_security_info(policy) and ca.requires_managed_device(policy)

    return ca_coverage_result(
        label="Managed device for MFA registration",
        policies=_policies(evidence),
        predicate=_pred,
        justified=break_glass_principal_ids(evidence),
        ok_summary=(
            "Enforced Conditional Access requires a managed device to register "
            "security information."
        ),
        ok_customer=("People can only set up multi-factor authentication from managed devices."),
        gap_summary=("No enforced policy requires a managed device for MFA registration."),
        gap_customer=(
            "Attackers with a stolen password may register their own multi-factor method."
        ),
    )


def evaluate_ca_device_code_block(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return ca_coverage_result(
        label="Device code flow block",
        policies=_policies(evidence),
        predicate=ca.is_device_code_block,
        justified=break_glass_principal_ids(evidence),
        ok_summary="Enforced Conditional Access blocks device code authentication flow.",
        ok_customer="The device-code sign-in flow used in phishing kits is blocked.",
        gap_summary="No enforced Conditional Access policy blocks device code flow.",
        gap_customer="Device-code phishing can still complete a successful sign-in.",
    )

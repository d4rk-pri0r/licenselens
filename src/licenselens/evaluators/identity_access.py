"""Conditional Access and Identity Protection evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.collectors import conditional_access as ca
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, ExposureClass, FindingStatus

_BREAK_GLASS_NOTE: Final = (
    "Break-glass (emergency access) accounts are often excluded from MFA on "
    "purpose — confirm exclusions in Conditional Access before changing anything."
)


def _legacy_auth_exposed(*, enforced: bool, report_only: bool, sd_enabled: bool = False) -> bool:
    """EXPOSED when legacy auth is broadly allowed with no block and no monitoring.

    Security Defaults, when enabled, provides baseline legacy-auth blocking
    that clears this exposure flag even when CA policies are absent.
    """
    if sd_enabled:
        return False
    return not enforced and not report_only


def _mfa_less_privileged_exposed(
    *,
    privileged_principals: int,
    mfa_enforced: bool,
    mfa_report_only: bool,
) -> bool:
    """EXPOSED when privileged principals exist with no enforced MFA coverage.

    Report-only MFA still leaves a live MFA-less path today, so it does not
    clear the rubric. Break-glass exclusions are the documented exception.
    """
    return privileged_principals > 0 and not mfa_enforced


def evaluate_ca_priv_gaps(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess MFA coverage and legacy-auth blocking via Conditional Access."""
    del check  # metadata unused; signature shared with registry
    from licenselens.collectors import privileged_roles as priv

    policies: list[dict[str, Any]] = list(evidence.get("ca_policies") or [])
    assignments: list[dict[str, Any]] = list(evidence.get("role_assignments") or [])
    enabled = [p for p in policies if ca.is_enabled(p)]
    report_only = [p for p in policies if ca.is_report_only(p)]

    mfa_enforced = [
        p
        for p in enabled
        if ca.requires_mfa(p) and (ca.includes_all_users(p) or ca.targets_privileged_roles(p))
    ]
    mfa_report = [
        p
        for p in report_only
        if ca.requires_mfa(p) and (ca.includes_all_users(p) or ca.targets_privileged_roles(p))
    ]
    legacy_enforced = [p for p in enabled if ca.is_legacy_auth_block(p)]
    legacy_report = [p for p in report_only if ca.is_legacy_auth_block(p)]

    priv_asg = priv.filter_privileged_assignments(assignments)
    privileged_principal_count = len(
        {str(a.get("principalId")) for a in priv_asg if a.get("principalId")}
    )
    ga_standing = [
        a
        for a in priv_asg
        if str(a.get("roleDefinitionId") or "").lower() == priv.GLOBAL_ADMIN_TEMPLATE_ID.lower()
    ]

    sd_policy = evidence.get("security_defaults_policy") or {}
    sd_enabled = bool(sd_policy.get("isEnabled")) if isinstance(sd_policy, dict) else False

    exposure_flags: list[str] = []
    limitations: list[str] = []
    if _legacy_auth_exposed(
        enforced=bool(legacy_enforced),
        report_only=bool(legacy_report),
        sd_enabled=sd_enabled,
    ):
        exposure_flags.append("legacy_auth_broadly_allowed")
    if _mfa_less_privileged_exposed(
        privileged_principals=privileged_principal_count,
        mfa_enforced=bool(mfa_enforced),
        mfa_report_only=bool(mfa_report),
    ):
        exposure_flags.append("mfa_missing_for_privileged")
        limitations.append(_BREAK_GLASS_NOTE)

    exposure_class = ExposureClass.EXPOSED if exposure_flags else ExposureClass.NONE

    evidence_out = {
        "policy_count": len(policies),
        "enabled_count": len(enabled),
        "report_only_count": len(report_only),
        "mfa_enforced_policies": [p.get("displayName") for p in mfa_enforced],
        "mfa_report_only_policies": [p.get("displayName") for p in mfa_report],
        "legacy_block_enforced": [p.get("displayName") for p in legacy_enforced],
        "legacy_block_report_only": [p.get("displayName") for p in legacy_report],
        "privileged_principal_count": privileged_principal_count,
        "global_admin_standing_count": len(ga_standing),
        "mfa_covers_privileged": bool(mfa_enforced),
        "mfa_report_only_covers_privileged": bool(mfa_report),
        "exposure_flags": exposure_flags,
    }

    if not policies:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Conditional Access policies were found.",
            evidence=evidence_out,
            customer_summary=(
                "We did not find sign-in rules that require extra verification. "
                "Powerful accounts may be able to sign in with only a password."
            ),
            exposure_class=exposure_class,
            limitations=limitations,
        )

    has_mfa = bool(mfa_enforced)
    has_legacy = bool(legacy_enforced)
    has_mfa_ro = bool(mfa_report)
    has_legacy_ro = bool(legacy_report)

    exposure_sentence = ""
    if "legacy_auth_broadly_allowed" in exposure_flags:
        exposure_sentence += (
            " EXPOSED: outdated sign-in methods that skip modern security checks "
            "are broadly allowed right now."
        )
    if "mfa_missing_for_privileged" in exposure_flags:
        exposure_sentence += (
            " EXPOSED: privileged admin accounts can currently sign in without "
            "enforced multi-factor authentication."
        )

    if has_mfa and has_legacy:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Enforced Conditional Access requires MFA for users/admins and "
                "blocks legacy authentication clients."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Strong sign-in rules look enforced: extra verification is required "
                "and outdated sign-in methods are blocked."
            ),
            exposure_class=exposure_class,
            limitations=limitations,
        )

    if has_mfa or has_legacy or has_mfa_ro or has_legacy_ro:
        missing: list[str] = []
        if not has_mfa:
            missing.append(
                "enforced MFA for all users or privileged roles"
                + (" (report-only MFA exists)" if has_mfa_ro else "")
            )
        if not has_legacy:
            missing.append(
                "enforced legacy authentication block"
                + (" (report-only legacy block exists)" if has_legacy_ro else "")
            )
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Conditional Access is partially configured: missing "
            + "; ".join(missing)
            + ".",
            evidence=evidence_out,
            customer_summary=(
                "Some sign-in protections are present, but the full set is not "
                "enforced yet (multi-factor authentication and/or blocking outdated "
                "sign-in methods)." + exposure_sentence
            ),
            exposure_class=exposure_class,
            limitations=limitations,
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"Found {len(policies)} Conditional Access policy(ies), but none "
            "clearly enforce MFA for users/admins or block legacy authentication."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Sign-in rules may exist, but they do not clearly require strong "
            "verification for important accounts or block outdated sign-in methods."
            + exposure_sentence
        ),
        exposure_class=exposure_class,
        limitations=limitations,
    )

"""Check evaluators — pure functions over collected evidence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from licenselens.collectors import conditional_access as ca
from licenselens.models import CheckDefinition, FindingStatus


@dataclass
class Evaluation:
    status: FindingStatus
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    # Optional overrides for customer-facing copy when status is nuanced
    customer_summary: str | None = None


Evaluator = Callable[[CheckDefinition, dict[str, Any]], Evaluation]


def evaluate_ca_priv_gaps(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess MFA coverage and legacy-auth blocking via Conditional Access."""
    del check  # metadata unused; signature shared with registry
    policies: list[dict[str, Any]] = list(evidence.get("ca_policies") or [])
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

    evidence_out = {
        "policy_count": len(policies),
        "enabled_count": len(enabled),
        "report_only_count": len(report_only),
        "mfa_enforced_policies": [p.get("displayName") for p in mfa_enforced],
        "mfa_report_only_policies": [p.get("displayName") for p in mfa_report],
        "legacy_block_enforced": [p.get("displayName") for p in legacy_enforced],
        "legacy_block_report_only": [p.get("displayName") for p in legacy_report],
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
        )

    has_mfa = bool(mfa_enforced)
    has_legacy = bool(legacy_enforced)
    has_mfa_ro = bool(mfa_report)
    has_legacy_ro = bool(legacy_report)

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
                "sign-in methods)."
            ),
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
        ),
    )


def evaluate_idprotect_off(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess risk-based Conditional Access (Identity Protection outcomes)."""
    del check
    policies: list[dict[str, Any]] = list(evidence.get("ca_policies") or [])
    risk_policies = [p for p in policies if ca.has_risk_conditions(p)]

    def _enforced_risk(kind: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in risk_policies:
            if not ca.is_enabled(p):
                continue
            levels = (
                ca.sign_in_risk_levels(p) if kind == "sign_in" else ca.user_risk_levels(p)
            )
            if not levels:
                continue
            controls = {
                str(c).lower()
                for c in ((p.get("grantControls") or {}).get("builtInControls") or [])
            }
            if ca.requires_mfa(p) or ca.is_block_policy(p) or "passwordchange" in controls:
                out.append(p)
        return out

    def _report_risk(kind: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in risk_policies:
            if not ca.is_report_only(p):
                continue
            levels = (
                ca.sign_in_risk_levels(p) if kind == "sign_in" else ca.user_risk_levels(p)
            )
            if levels:
                out.append(p)
        return out

    sign_in_enforced = _enforced_risk("sign_in")
    user_enforced = _enforced_risk("user")
    sign_in_report = _report_risk("sign_in")
    user_report = _report_risk("user")

    evidence_out = {
        "risk_policy_count": len(risk_policies),
        "sign_in_risk_enforced": [p.get("displayName") for p in sign_in_enforced],
        "user_risk_enforced": [p.get("displayName") for p in user_enforced],
        "sign_in_risk_report_only": [p.get("displayName") for p in sign_in_report],
        "user_risk_report_only": [p.get("displayName") for p in user_report],
    }

    if sign_in_enforced and user_enforced:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Enforced Conditional Access policies address both sign-in risk "
                "and user risk (Identity Protection outcomes)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Suspicious sign-ins and risky accounts appear to trigger automatic "
                "extra checks or blocks."
            ),
        )

    if sign_in_enforced or user_enforced or sign_in_report or user_report:
        bits: list[str] = []
        if not sign_in_enforced:
            bits.append(
                "enforced sign-in risk policy"
                + (" (report-only present)" if sign_in_report else " missing")
            )
        if not user_enforced:
            bits.append(
                "enforced user risk policy"
                + (" (report-only present)" if user_report else " missing")
            )
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Identity Protection–style risk controls are incomplete: "
            + "; ".join(bits)
            + ".",
            evidence=evidence_out,
            customer_summary=(
                "Some suspicious-sign-in protections exist, but they are incomplete "
                "or still in report-only mode — risky logins may not be stopped."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            "No Conditional Access policies with user-risk or sign-in-risk "
            "conditions were found (Identity Protection not operationalized via CA)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "We did not find automatic responses when Microsoft marks a sign-in "
            "or account as risky. That protection may still be turned off."
        ),
    )


def evaluate_pim_unused(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess whether privileged access uses PIM eligibility vs standing roles."""
    del check
    from licenselens.collectors import privileged_roles as priv

    assignments = list(evidence.get("role_assignments") or [])
    eligibilities = list(evidence.get("role_eligibilities") or [])

    priv_asg = priv.filter_privileged_assignments(assignments)
    priv_elig = priv.filter_privileged_eligibilities(eligibilities)

    permanent_principals = {
        str(a.get("principalId")) for a in priv_asg if a.get("principalId")
    }
    eligible_principals = {
        str(s.get("principalId")) for s in priv_elig if s.get("principalId")
    }
    ga_standing = [
        a
        for a in priv_asg
        if str(a.get("roleDefinitionId") or "").lower()
        == priv.GLOBAL_ADMIN_TEMPLATE_ID.lower()
    ]

    evidence_out = {
        "privileged_permanent_assignments": len(priv_asg),
        "privileged_eligible_schedules": len(priv_elig),
        "privileged_permanent_principals": len(permanent_principals),
        "privileged_eligible_principals": len(eligible_principals),
        "global_admin_standing_assignments": len(ga_standing),
        "sample_standing_roles": sorted(
            {
                priv.ROLE_DISPLAY_NAMES.get(
                    str(a.get("roleDefinitionId")),
                    str(a.get("roleDefinitionId")),
                )
                for a in priv_asg[:20]
            }
        ),
    }

    if not priv_asg and not priv_elig:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No privileged directory role assignments or PIM eligibilities "
                "were found in the scanned role set."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not find high-privilege admin assignments in the usual "
                "role list. Confirm directory permissions, or you may use a "
                "different admin model."
            ),
        )

    if priv_asg and not priv_elig:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Found {len(priv_asg)} standing privileged role assignment(s) and "
                "0 PIM eligible schedules — just-in-time admin access is not in use."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Admin superpowers appear permanently on. Time-limited admin access "
                "(included in your stronger identity plan) does not look like it is "
                "being used."
            ),
        )

    if ga_standing and len(ga_standing) >= 2 and len(priv_elig) < len(priv_asg):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"PIM eligibilities exist ({len(priv_elig)}), but "
                f"{len(priv_asg)} standing privileged assignments remain "
                f"(including {len(ga_standing)} Global Administrator)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some just-in-time admin access is configured, but several powerful "
                "accounts still have permanent admin rights."
            ),
        )

    if len(priv_elig) >= len(priv_asg) and len(ga_standing) <= 1:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Privileged access appears PIM-oriented: eligible schedules are "
                "present and standing privileged assignments are limited."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Admin access looks closer to 'only when needed' rather than "
                "always-on superpowers for many people."
            ),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Mixed privileged access model: {len(priv_asg)} standing assignment(s), "
            f"{len(priv_elig)} PIM eligible schedule(s)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Your organization has started using time-limited admin access, but "
            "permanent high-power roles are still common."
        ),
    )


def evaluate_dormant_privileged(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Find enabled privileged principals with no successful sign-in in lookback."""
    del check
    from licenselens.collectors import privileged_roles as priv

    assignments = list(evidence.get("role_assignments") or [])
    recent_signins: set[str] = set(evidence.get("recent_signin_user_ids") or [])
    directory: dict[str, Any] = dict(evidence.get("principal_directory") or {})
    lookback_days = int(evidence.get("signin_lookback_days") or 90)
    signin_truncated = bool(evidence.get("signin_sample_truncated"))

    priv_asg = priv.filter_privileged_assignments(assignments)
    principal_ids = sorted(
        {str(a.get("principalId")) for a in priv_asg if a.get("principalId")}
    )

    dormant_users: list[dict[str, str]] = []
    active_users = 0
    disabled_or_unknown = 0
    non_user_principals = 0

    for pid in principal_ids:
        obj = directory.get(pid) or {}
        odata = str(obj.get("@odata.type") or "")
        # Users typically have userPrincipalName; groups/SPs counted separately
        upn = obj.get("userPrincipalName")
        account_enabled = obj.get("accountEnabled")

        if upn is None and "user" not in odata.lower():
            # group or service principal holding a role
            if obj:
                non_user_principals += 1
            else:
                disabled_or_unknown += 1
            continue

        if account_enabled is False:
            disabled_or_unknown += 1
            continue

        if pid in recent_signins:
            active_users += 1
            continue

        # Enabled user (or unknown type with UPN) without recent success sign-in
        dormant_users.append(
            {
                "id": pid,
                # Redact local-part in default evidence for safer reports
                "userPrincipalName": _redact_upn(str(upn)) if upn else pid,
            }
        )

    evidence_out = {
        "privileged_principal_count": len(principal_ids),
        "active_privileged_users": active_users,
        "dormant_privileged_users": len(dormant_users),
        "non_user_privileged_principals": non_user_principals,
        "disabled_or_unresolved": disabled_or_unknown,
        "lookback_days": lookback_days,
        "signin_sample_truncated": signin_truncated,
        "dormant_sample": dormant_users[:10],
    }

    if not principal_ids:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No privileged role principals were found to evaluate for dormancy.",
            evidence=evidence_out,
            customer_summary=(
                "We could not list high-privilege accounts to check for inactivity."
            ),
        )

    if not dormant_users:
        summary = (
            f"No enabled privileged users without successful sign-in in "
            f"{lookback_days} days were found "
            f"({active_users} active privileged user(s) observed)."
        )
        if signin_truncated:
            summary += " Sign-in sampling was truncated; results may be incomplete."
        return Evaluation(
            status=FindingStatus.OK if not signin_truncated else FindingStatus.PARTIAL,
            summary=summary,
            evidence=evidence_out,
            customer_summary=(
                "High-privilege accounts we could check appear to have been used "
                "recently (or are disabled)."
                + (
                    " Note: sign-in history sampling was limited in large tenants."
                    if signin_truncated
                    else ""
                )
            ),
        )

    status = FindingStatus.GAP if len(dormant_users) >= 2 else FindingStatus.PARTIAL
    return Evaluation(
        status=status,
        summary=(
            f"Found {len(dormant_users)} enabled privileged user(s) with no successful "
            f"sign-in in the last {lookback_days} days "
            f"(of {len(principal_ids)} privileged principal(s))."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Some powerful accounts are still switched on but have not been used "
            "recently. Unused admin accounts are a favorite target for attackers."
        ),
    )


def _redact_upn(upn: str) -> str:
    if "@" not in upn:
        return "***"
    local, _, domain = upn.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


EVALUATORS: dict[str, Evaluator] = {
    "id-ca-priv-gaps": evaluate_ca_priv_gaps,
    "id-idprotect-off": evaluate_idprotect_off,
    "id-pim-unused": evaluate_pim_unused,
    "id-dormant-privileged": evaluate_dormant_privileged,
}

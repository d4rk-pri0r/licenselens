"""Privileged role and dormant admin evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus


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

    permanent_principals = {str(a.get("principalId")) for a in priv_asg if a.get("principalId")}
    eligible_principals = {str(s.get("principalId")) for s in priv_elig if s.get("principalId")}
    ga_standing = [
        a
        for a in priv_asg
        if str(a.get("roleDefinitionId") or "").lower() == priv.GLOBAL_ADMIN_TEMPLATE_ID.lower()
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
    principal_ids = sorted({str(a.get("principalId")) for a in priv_asg if a.get("principalId")})

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
            customer_summary=("We could not list high-privilege accounts to check for inactivity."),
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

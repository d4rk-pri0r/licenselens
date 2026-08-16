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
    break_glass = {str(x) for x in evidence.get("break_glass_principal_ids") or ()}

    priv_asg = priv.filter_privileged_assignments(assignments)
    priv_elig = priv.filter_privileged_eligibilities(eligibilities)

    permanent_principals = {str(a.get("principalId")) for a in priv_asg if a.get("principalId")}
    eligible_principals = {str(s.get("principalId")) for s in priv_elig if s.get("principalId")}
    ga_standing = [
        a
        for a in priv_asg
        if str(a.get("roleDefinitionId") or "").lower() == priv.GLOBAL_ADMIN_TEMPLATE_ID.lower()
    ]
    standing_non_bg = [a for a in priv_asg if str(a.get("principalId")) not in break_glass]
    standing_roles = {str(a.get("roleDefinitionId") or "") for a in priv_asg}
    eligible_roles = {str(s.get("roleDefinitionId") or "") for s in priv_elig}
    uncovered_standing_roles = sorted(standing_roles - eligible_roles)

    evidence_out = {
        "privileged_permanent_assignments": len(priv_asg),
        "privileged_eligible_schedules": len(priv_elig),
        "privileged_permanent_principals": len(permanent_principals),
        "privileged_eligible_principals": len(eligible_principals),
        "global_admin_standing_assignments": len(ga_standing),
        "break_glass_standing_assignments": len(priv_asg) - len(standing_non_bg),
        "standing_non_break_glass_assignments": len(standing_non_bg),
        "uncovered_standing_roles": [
            priv.ROLE_DISPLAY_NAMES.get(role, role) for role in uncovered_standing_roles
        ],
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

    if not standing_non_bg and priv_elig and not uncovered_standing_roles:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Privileged access appears PIM-oriented: standing privileged "
                "assignments exist only for break-glass principals and eligible "
                "schedules cover those roles."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Admin access looks closer to 'only when needed' rather than "
                "always-on superpowers for many people."
            ),
        )

    if not standing_non_bg and priv_elig and uncovered_standing_roles:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Standing privileged assignments are limited to break-glass "
                "principals, but PIM eligible schedules do not cover role(s): "
                + ", ".join(uncovered_standing_roles)
                + "."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Emergency accounts still hold permanent roles, and those roles "
                "do not yet have just-in-time coverage."
            ),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Mixed privileged access model: {len(standing_non_bg)} standing "
            f"privileged assignment(s) beyond break-glass principals, "
            f"{len(priv_elig)} PIM eligible schedule(s)"
            + (f", including {len(ga_standing)} Global Administrator" if ga_standing else "")
            + "."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Your organization has started using time-limited admin access, but "
            "permanent high-power roles are still common."
        ),
    )


def _is_service_principal(obj: dict[str, Any]) -> bool:
    odata = str(obj.get("@odata.type") or "").lower()
    if "serviceprincipal" in odata:
        return True
    return "appId" in obj and obj.get("userPrincipalName") is None and "group" not in odata


def _has_credential_data(obj: dict[str, Any]) -> bool:
    return "keyCredentials" in obj or "passwordCredentials" in obj


def _has_credentials(obj: dict[str, Any]) -> bool:
    return bool(list(obj.get("keyCredentials") or []) + list(obj.get("passwordCredentials") or []))


def evaluate_dormant_privileged(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Find enabled privileged principals with no successful sign-in in lookback."""
    del check
    from licenselens.collectors import privileged_roles as priv

    assignments = list(evidence.get("role_assignments") or [])
    recent_signins: set[str] = set(evidence.get("recent_signin_user_ids") or [])
    recent_sp_activity: set[str] = set(evidence.get("recent_signin_service_principal_ids") or [])
    directory: dict[str, Any] = dict(evidence.get("principal_directory") or {})
    lookback_days = int(evidence.get("signin_lookback_days") or 90)
    signin_truncated = bool(evidence.get("signin_sample_truncated"))

    priv_asg = priv.filter_privileged_assignments(assignments)
    principal_ids = sorted({str(a.get("principalId")) for a in priv_asg if a.get("principalId")})

    dormant_users: list[dict[str, str]] = []
    dormant_workload: list[dict[str, str]] = []
    unverifiable_workload: list[dict[str, str]] = []
    active_users = 0
    active_workload = 0
    disabled_or_unknown = 0
    non_user_principals = 0

    for pid in principal_ids:
        obj = directory.get(pid) or {}
        odata = str(obj.get("@odata.type") or "")
        upn = obj.get("userPrincipalName")
        account_enabled = obj.get("accountEnabled")

        if _is_service_principal(obj):
            if account_enabled is False:
                disabled_or_unknown += 1
                continue
            if _has_credential_data(obj) and not _has_credentials(obj):
                # Enabled SP with no credentials at all: nothing can authenticate,
                # so the privileged workload identity is unused.
                dormant_workload.append(
                    {
                        "id": pid,
                        "principal_type": "servicePrincipal",
                        "appId": str(obj.get("appId") or ""),
                    }
                )
                continue
            sp_ids = {pid, str(obj.get("appId") or "")}
            if (recent_signins & sp_ids) or (recent_sp_activity & sp_ids):
                active_workload += 1
                continue
            # Enabled SP with credentials but no usage signal available.
            unverifiable_workload.append(
                {
                    "id": pid,
                    "principal_type": "servicePrincipal",
                    "appId": str(obj.get("appId") or ""),
                }
            )
            continue

        if upn is None and "user" not in odata.lower():
            # group or other non-user principal holding a role
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
        "active_workload_identities": active_workload,
        "dormant_workload_identities": len(dormant_workload),
        "unverifiable_workload_identities": len(unverifiable_workload),
        "non_user_privileged_principals": non_user_principals,
        "disabled_or_unresolved": disabled_or_unknown,
        "lookback_days": lookback_days,
        "signin_sample_truncated": signin_truncated,
        "dormant_sample": dormant_users[:10],
        "dormant_workload_sample": dormant_workload[:10],
    }

    if not principal_ids:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No privileged role principals were found to evaluate for dormancy.",
            evidence=evidence_out,
            customer_summary=("We could not list high-privilege accounts to check for inactivity."),
        )

    total_dormant = len(dormant_users) + len(dormant_workload)
    workload_note = (
        f" {len(unverifiable_workload)} enabled service principal(s) hold privileged "
        "roles, but workload identity activity could not be verified from the "
        "collected sign-in data."
        if unverifiable_workload
        else ""
    )

    if total_dormant:
        summary = (
            f"Found {total_dormant} enabled privileged principal(s) with no "
            f"successful sign-in or workload activity in the last {lookback_days} "
            f"days ({len(dormant_users)} user(s), {len(dormant_workload)} workload "
            f"identit{'y' if len(dormant_workload) == 1 else 'ies'} of "
            f"{len(principal_ids)} privileged principal(s))."
        )
        if unverifiable_workload:
            summary += workload_note
        status = FindingStatus.GAP if total_dormant >= 2 else FindingStatus.PARTIAL
        return Evaluation(
            status=status,
            summary=summary,
            evidence=evidence_out,
            customer_summary=(
                "Some powerful accounts are still switched on but have not been used "
                "recently. Unused admin accounts and workload identities are a "
                "favorite target for attackers."
            ),
        )

    if unverifiable_workload:
        summary = (
            f"No dormant privileged user was found ({active_users} active privileged "
            "user(s) observed), but " + workload_note.lstrip()
        )
        if signin_truncated:
            summary += " Sign-in sampling was truncated; results may be incomplete."
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=summary,
            evidence=evidence_out,
            customer_summary=(
                "High-privilege accounts we could check appear to have been used "
                "recently, but workload identities holding privileged roles could "
                "not be verified — review their credential and sign-in activity."
            ),
        )

    summary = (
        f"No enabled privileged principals without recent activity in "
        f"{lookback_days} days were found "
        f"({active_users} active privileged user(s), {active_workload} active "
        f"workload identit{'y' if active_workload == 1 else 'ies'} observed)."
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


def _redact_upn(upn: str) -> str:
    if "@" not in upn:
        return "***"
    local, _, domain = upn.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"

"""Additional privileged-account posture evaluators (GA bounds, cloud-only)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.privileged_roles import (
    GLOBAL_ADMIN_TEMPLATE_ID,
    filter_highly_privileged_assignments,
    filter_privileged_assignments,
)
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus


def evaluate_ga_count_bounds(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    assignments = list(evidence.get("role_assignments") or [])
    ga = [
        a
        for a in assignments
        if str(a.get("roleDefinitionId") or "").lower() == GLOBAL_ADMIN_TEMPLATE_ID.lower()
    ]
    principals = sorted({str(a.get("principalId")) for a in ga if a.get("principalId")})
    count = len(principals)
    evidence_out = {
        "global_admin_principal_count": count,
        "global_admin_assignment_count": len(ga),
        "min_recommended": 2,
        "max_recommended": 8,
    }
    if 2 <= count <= 8:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"Global Administrator principal count is within bounds ({count}).",
            evidence=evidence_out,
            customer_summary=(
                "You have enough Global Admins for break-glass coverage without too many."
            ),
        )
    if count < 2:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"Only {count} Global Administrator principal(s); minimum recommended is 2.",
            evidence=evidence_out,
            customer_summary=("Too few Global Admins increases lockout risk during an emergency."),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=f"Found {count} Global Administrator principals; maximum recommended is 8.",
        evidence=evidence_out,
        customer_summary=(
            "Too many permanent Global Admins expands the blast radius of a compromise."
        ),
    )


def evaluate_ga_finer_roles(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    assignments = list(evidence.get("role_assignments") or [])
    ga = [
        a
        for a in assignments
        if str(a.get("roleDefinitionId") or "").lower() == GLOBAL_ADMIN_TEMPLATE_ID.lower()
    ]
    other = filter_highly_privileged_assignments(
        [
            a
            for a in assignments
            if str(a.get("roleDefinitionId") or "").lower() != GLOBAL_ADMIN_TEMPLATE_ID.lower()
        ]
    )
    ga_principals = {str(a.get("principalId")) for a in ga if a.get("principalId")}
    evidence_out = {
        "global_admin_principals": len(ga_principals),
        "other_highly_privileged_assignments": len(other),
    }
    if len(ga_principals) <= 8 and other:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Finer-grained privileged roles are in use alongside a bounded "
                "Global Administrator set."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Admins appear to use more specific roles instead of Global Admin for everything."
            ),
        )
    if len(ga_principals) > 8 and not other:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Many Global Administrators and few finer-grained privileged roles were found."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Day-to-day admin work may be using Global Admin instead of narrower roles."
            ),
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Mixed privileged model: {len(ga_principals)} Global Admin principal(s), "
            f"{len(other)} other highly privileged assignment(s)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Some finer-grained admin roles exist, but Global Admin may still be overused."
        ),
    )


def evaluate_priv_cloud_only(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    assignments = filter_privileged_assignments(list(evidence.get("role_assignments") or []))
    directory = dict(evidence.get("principal_directory") or {})
    hybrid: list[str] = []
    cloud_only = 0
    unknown = 0
    for assignment in assignments:
        pid = str(assignment.get("principalId") or "")
        obj = directory.get(pid) or {}
        upn = str(obj.get("userPrincipalName") or "")
        on_prem = obj.get("onPremisesSyncEnabled")
        if on_prem is True or (upn and "#ext#" not in upn.lower() and on_prem is True):
            hybrid.append(pid)
        elif on_prem is False or obj.get("userPrincipalName"):
            cloud_only += 1
        else:
            unknown += 1
    evidence_out = {
        "privileged_principals_checked": len(assignments),
        "cloud_only": cloud_only,
        "hybrid_or_synced": len(hybrid),
        "unknown": unknown,
        "hybrid_sample": hybrid[:10],
    }
    if hybrid:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Found {len(hybrid)} privileged principal(s) synced from on-premises directories."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some powerful admin accounts are tied to on-premises identity, "
                "which expands compromise paths."
            ),
        )
    if unknown and not cloud_only:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Could not determine cloud-only status for privileged principals.",
            evidence=evidence_out,
            customer_summary=("We could not confirm whether admin accounts are cloud-only."),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Privileged principals appear cloud-only (not on-premises synced).",
        evidence=evidence_out,
        customer_summary="Powerful admin accounts look separate from on-premises directories.",
    )


def evaluate_password_never_expire(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    domains = list(evidence.get("domains") or [])
    expiring = []
    never = []
    for domain in domains:
        if not domain.get("isVerified", True):
            continue
        days = domain.get("passwordValidityPeriodInDays")
        name = str(domain.get("id") or "?")
        if days is None:
            continue
        try:
            value = int(days)
        except (TypeError, ValueError):
            continue
        if value == 2147483647 or value <= 0:
            never.append(name)
        else:
            expiring.append({"domain": name, "days": value})
    evidence_out = {
        "never_expire_domains": never,
        "expiring_domains": expiring,
    }
    if expiring:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "One or more verified domains still enforce password expiration: "
                + ", ".join(f"{row['domain']} ({row['days']}d)" for row in expiring[:5])
            ),
            evidence=evidence_out,
            customer_summary=(
                "Passwords still expire on a schedule. Modern guidance is to ban "
                "periodic expiration and use strong multi-factor authentication instead."
            ),
        )
    if never or domains:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Verified domains do not enforce periodic password expiration.",
            evidence=evidence_out,
            customer_summary="Passwords are not forced to rotate on a calendar.",
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="Domain password validity settings were not available.",
        evidence=evidence_out,
        customer_summary="We could not confirm password expiration policy for your domains.",
    )

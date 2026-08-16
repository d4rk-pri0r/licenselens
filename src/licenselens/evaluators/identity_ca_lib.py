"""Shared Conditional Access evaluation helpers for identity checks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from licenselens.collectors import conditional_access as ca
from licenselens.evaluators.common import Evaluation
from licenselens.models import FindingStatus

PolicyPred = Callable[[dict[str, Any]], bool]

_BREAK_GLASS_LIMITATION: Final = (
    "Named break-glass exclusions require a profile exclusion with kind=break_glass, "
    "owner, reason, and principal_ids."
)


def break_glass_principal_ids(evidence: dict[str, Any]) -> set[str]:
    raw = evidence.get("break_glass_principal_ids") or []
    return {str(item).lower() for item in raw if item}


def enabled_matching(
    policies: list[dict[str, Any]],
    predicate: PolicyPred,
) -> list[dict[str, Any]]:
    return [p for p in policies if ca.is_enabled(p) and predicate(p)]


def report_only_matching(
    policies: list[dict[str, Any]],
    predicate: PolicyPred,
) -> list[dict[str, Any]]:
    return [p for p in policies if ca.is_report_only(p) and predicate(p)]


def names(policies: list[dict[str, Any]]) -> list[str]:
    return [str(p.get("displayName") or p.get("id") or "?") for p in policies]


def exclusion_issues(
    policies: list[dict[str, Any]],
    justified: set[str],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for policy in policies:
        bad = ca.unjustified_exclusions(policy, justified)
        if bad:
            issues.append(
                {
                    "policy": policy.get("displayName") or policy.get("id"),
                    "unjustified_exclusions": bad,
                }
            )
    return issues


def ca_coverage_result(
    *,
    label: str,
    policies: list[dict[str, Any]],
    predicate: PolicyPred,
    justified: set[str],
    require_all_users: bool = True,
    ok_summary: str,
    ok_customer: str,
    gap_summary: str,
    gap_customer: str,
) -> Evaluation:
    enforced = enabled_matching(policies, predicate)
    report_only = report_only_matching(policies, predicate)
    if require_all_users:
        enforced = [p for p in enforced if ca.includes_all_users(p)]
        report_only = [p for p in report_only if ca.includes_all_users(p)]

    issues = exclusion_issues(enforced, justified)
    evidence_out: dict[str, Any] = {
        "label": label,
        "enforced_policies": names(enforced),
        "report_only_policies": names(report_only),
        "unjustified_exclusion_issues": issues,
        "break_glass_principal_count": len(justified),
    }
    limitations: list[str] = []
    if issues:
        limitations.append(_BREAK_GLASS_LIMITATION)

    if enforced and not issues:
        return Evaluation(
            status=FindingStatus.OK,
            summary=ok_summary,
            evidence=evidence_out,
            customer_summary=ok_customer,
            limitations=limitations,
        )
    if enforced and issues:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{label}: enforced policy present, but exclusions lack named "
                "break-glass rationale in this report's configuration."
            ),
            evidence=evidence_out,
            customer_summary=(
                "A protective sign-in rule is on, but some accounts are excluded "
                "without a documented emergency-access rationale."
            ),
            limitations=limitations,
        )
    if report_only:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"{label}: only report-only Conditional Access coverage found.",
            evidence=evidence_out,
            customer_summary=(
                "A matching sign-in rule exists in report-only mode, so it is not enforced yet."
            ),
            limitations=limitations,
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=gap_summary,
        evidence=evidence_out,
        customer_summary=gap_customer,
        limitations=limitations,
    )


def role_targeted_result(
    *,
    label: str,
    policies: list[dict[str, Any]],
    predicate: PolicyPred,
    role_ids: set[str],
    justified: set[str],
    ok_summary: str,
    ok_customer: str,
    gap_summary: str,
    gap_customer: str,
) -> Evaluation:
    def _targets(policy: dict[str, Any]) -> bool:
        if not predicate(policy):
            return False
        if ca.includes_all_users(policy):
            return True
        roles = ca.included_roles(policy)
        return bool(roles & {r.lower() for r in role_ids})

    return ca_coverage_result(
        label=label,
        policies=policies,
        predicate=_targets,
        justified=justified,
        require_all_users=False,
        ok_summary=ok_summary,
        ok_customer=ok_customer,
        gap_summary=gap_summary,
        gap_customer=gap_customer,
    )

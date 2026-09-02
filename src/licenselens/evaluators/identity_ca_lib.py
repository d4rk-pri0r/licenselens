"""Shared Conditional Access evaluation helpers for identity checks."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any, Final

from licenselens.collectors import conditional_access as ca
from licenselens.evaluators.common import Evaluation
from licenselens.models import FindingStatus

PolicyPred = Callable[[dict[str, Any]], bool]
ScopeFn = Callable[[dict[str, Any]], ca.PolicyScope]


def purpose_scope(**cleared: Any) -> ScopeFn:
    """Scope function that treats the named dimensions as the policy's purpose.

    A role-targeted, risk-conditioned, or user-action policy is not "scoped" by the
    very dimension that defines it; every other dimension still counts as a gap.
    """

    def _scope(policy: dict[str, Any]) -> ca.PolicyScope:
        return dataclasses.replace(ca.policy_scope(policy), **cleared)

    return _scope


_BREAK_GLASS_LIMITATION: Final = (
    "Named break-glass exclusions require a profile exclusion with kind=break_glass, "
    "owner, reason, and principal_ids."
)

_JOINT_SCOPE_LIMITATION: Final = (
    "Joint coverage across several narrower Conditional Access policies is not "
    "computed; each scoped policy is listed so a reviewer can judge the union."
)

_SECURITY_DEFAULTS_GAP_NOTE: Final = (
    "Security Defaults is on; Conditional Access policies cannot be created until it is disabled."
)


def break_glass_principal_ids(evidence: dict[str, Any]) -> set[str]:
    raw = evidence.get("break_glass_principal_ids") or []
    return {str(item).lower() for item in raw if item}


def security_defaults_enabled(evidence: dict[str, Any]) -> bool:
    """True when the tenant's Security Defaults policy is enabled.

    Fail-closed: an absent, errored, or malformed read yields False, so a
    failed collection never invents baseline protection.
    """
    policy = evidence.get("security_defaults_policy") or {}
    return bool(policy.get("isEnabled")) if isinstance(policy, dict) else False


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
    scope_fn: ScopeFn = ca.policy_scope,
    security_defaults_enabled: bool = False,
    security_defaults_clears_gap: bool = False,
) -> Evaluation:
    enforced = enabled_matching(policies, predicate)
    report_only = report_only_matching(policies, predicate)
    if require_all_users:
        enforced = [p for p in enforced if ca.includes_all_users(p)]
        report_only = [p for p in report_only if ca.includes_all_users(p)]

    enforced_scopes = [(policy, scope_fn(policy)) for policy in enforced]
    enforced_universal = [policy for policy, scope in enforced_scopes if scope.is_universal]
    enforced_scoped = [
        (policy, scope) for policy, scope in enforced_scopes if not scope.is_universal
    ]
    ordered_scoped = sorted(
        enforced_scoped,
        key=lambda item: (len(item[1].gaps), names([item[0]])[0], str(item[0].get("id") or "")),
    )

    issues = exclusion_issues(enforced_universal, justified)
    evidence_out: dict[str, Any] = {
        "label": label,
        "enforced_policies": names(enforced),
        "universal_policies": names(enforced_universal),
        "scoped_policies": [
            {"policy": names([policy])[0], "gaps": list(scope.gaps)}
            for policy, scope in ordered_scoped
        ],
        "scope_gaps_best": list(ordered_scoped[0][1].gaps) if ordered_scoped else [],
        "report_only_policies": names(report_only),
        "unjustified_exclusion_issues": issues,
        "break_glass_principal_count": len(justified),
        "security_defaults_enabled": security_defaults_enabled,
    }
    limitations: list[str] = []
    if issues:
        limitations.append(_BREAK_GLASS_LIMITATION)

    if enforced_universal and not issues:
        return Evaluation(
            status=FindingStatus.OK,
            summary=ok_summary,
            evidence=evidence_out,
            customer_summary=ok_customer,
            limitations=limitations,
        )
    if enforced_universal and issues:
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
    if enforced_scoped:
        best_gaps = ordered_scoped[0][1].gaps
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"{label}: enforced policy exists but is scoped ({', '.join(best_gaps)}).",
            evidence=evidence_out,
            customer_summary=(
                "A protective sign-in rule is on, but it does not apply to "
                "everyone, everywhere, all the time — see the scope notes."
            ),
            limitations=[*limitations, _JOINT_SCOPE_LIMITATION],
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
    if security_defaults_enabled and security_defaults_clears_gap:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Baseline protection is provided by Security Defaults; the "
                "Conditional Access capability you license is not in use."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Microsoft's built-in baseline is on, so basic multi-factor and "
                "legacy-sign-in blocking are present. The customizable sign-in rules "
                "included in your plan are not in use."
            ),
            limitations=limitations,
        )
    if security_defaults_enabled:
        limitations = [*limitations, _SECURITY_DEFAULTS_GAP_NOTE]
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
    security_defaults_enabled: bool = False,
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
        scope_fn=purpose_scope(all_users=True),
        security_defaults_enabled=security_defaults_enabled,
    )

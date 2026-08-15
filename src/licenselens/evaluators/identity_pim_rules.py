"""PIM standing assignment and activation-rule evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.privileged_roles import (
    GLOBAL_ADMIN_TEMPLATE_ID,
    filter_highly_privileged_assignments,
)
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus


def _assignments(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return list(evidence.get("role_assignments") or [])


def _eligibilities(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return list(evidence.get("role_eligibilities") or [])


def _pim_bundle(evidence: dict[str, Any]) -> dict[str, Any]:
    bundle = evidence.get("pim_policies_bundle") or {}
    return bundle if isinstance(bundle, dict) else {}


def _rules_for_role(bundle: dict[str, Any], role_id: str) -> list[dict[str, Any]]:
    policies = list(bundle.get("policies") or [])
    assignments = list(bundle.get("assignments") or [])
    policy_ids = {
        str(a.get("policyId"))
        for a in assignments
        if str(a.get("roleDefinitionId") or "").lower() == role_id.lower()
    }
    rules: list[dict[str, Any]] = []
    for policy in policies:
        if policy_ids and str(policy.get("id")) not in policy_ids:
            continue
        rules.extend(list(policy.get("rules") or []))
    return rules


def _rule_type(rule: dict[str, Any]) -> str:
    return str(rule.get("@odata.type") or rule.get("id") or "").lower()


def evaluate_pim_no_permanent_privileged(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    standing = filter_highly_privileged_assignments(_assignments(evidence))
    evidence_out = {
        "standing_highly_privileged_assignments": len(standing),
        "eligible_schedules": len(_eligibilities(evidence)),
    }
    if not standing:
        return Evaluation(
            status=FindingStatus.OK,
            summary="No permanent highly privileged role assignments were found.",
            evidence=evidence_out,
            customer_summary="High-power admin roles are not permanently assigned.",
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=(f"Found {len(standing)} permanent highly privileged role assignment(s)."),
        evidence=evidence_out,
        customer_summary=("Some powerful admin roles are permanently on instead of just-in-time."),
    )


def evaluate_pim_no_outside_pam(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    standing = filter_highly_privileged_assignments(_assignments(evidence))
    elig = _eligibilities(evidence)
    evidence_out = {
        "standing_highly_privileged_assignments": len(standing),
        "eligible_schedules": len(elig),
    }
    if standing and not elig:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Highly privileged roles are assigned permanently with no PIM eligibility "
                "schedules — provisioning appears outside a PAM workflow."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Powerful admin access is granted permanently without a just-in-time system."
            ),
        )
    if standing:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"PIM is present, but {len(standing)} permanent highly privileged "
                "assignment(s) remain outside pure eligible activation."
            ),
            evidence=evidence_out,
            customer_summary=("Some admin access still bypasses just-in-time activation."),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Highly privileged access appears provisioned through PIM eligibility.",
        evidence=evidence_out,
        customer_summary="Powerful admin access looks managed through just-in-time activation.",
    )


def evaluate_pim_ga_activation_approval(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    rules = _rules_for_role(_pim_bundle(evidence), GLOBAL_ADMIN_TEMPLATE_ID)
    approval_rules = [
        r
        for r in rules
        if "approval" in _rule_type(r)
        and (
            bool(r.get("isApprovalRequired"))
            or bool((r.get("setting") or {}).get("isApprovalRequired"))
        )
    ]
    evidence_out = {
        "ga_rule_count": len(rules),
        "approval_required_rules": len(approval_rules),
    }
    if approval_rules:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Global Administrator activation requires approval.",
            evidence=evidence_out,
            customer_summary="Turning on Global Admin requires another person to approve.",
        )
    if not rules:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="PIM policy rules for Global Administrator were not available.",
            evidence=evidence_out,
            customer_summary="We could not confirm whether Global Admin activation needs approval.",
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Global Administrator activation does not require approval.",
        evidence=evidence_out,
        customer_summary=(
            "Someone eligible for Global Admin can turn it on without a second approver."
        ),
    )


def _notification_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rules if "notification" in _rule_type(r)]


def evaluate_pim_privileged_assignment_alert(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = _pim_bundle(evidence)
    rules = list((bundle.get("policies") or [{}])[0].get("rules") or []) if bundle else []
    # Prefer scanning all policy rules.
    all_rules: list[dict[str, Any]] = []
    for policy in list(bundle.get("policies") or []):
        all_rules.extend(list(policy.get("rules") or []))
    notes = _notification_rules(all_rules or rules)
    evidence_out = {"notification_rule_count": len(notes)}
    if notes:
        return Evaluation(
            status=FindingStatus.OK,
            summary="PIM notification rules exist for privileged role assignment events.",
            evidence=evidence_out,
            customer_summary="Admins get alerts when powerful roles are assigned.",
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No PIM notification rules were found for privileged role assignments.",
        evidence=evidence_out,
        customer_summary="Powerful role assignments may happen without an alert.",
    )


def evaluate_pim_ga_activation_alert(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    rules = _rules_for_role(_pim_bundle(evidence), GLOBAL_ADMIN_TEMPLATE_ID)
    notes = _notification_rules(rules)
    evidence_out = {"ga_notification_rules": len(notes)}
    if notes:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Global Administrator activation triggers notification rules.",
            evidence=evidence_out,
            customer_summary="Someone is notified when Global Admin is turned on.",
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No notification rule found for Global Administrator activation.",
        evidence=evidence_out,
        customer_summary="Global Admin can be activated without a clear alert path.",
    )


def evaluate_pim_other_activation_alert(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = _pim_bundle(evidence)
    all_rules: list[dict[str, Any]] = []
    for policy in list(bundle.get("policies") or []):
        all_rules.extend(list(policy.get("rules") or []))
    notes = _notification_rules(all_rules)
    evidence_out = {"notification_rule_count": len(notes)}
    if notes:
        return Evaluation(
            status=FindingStatus.OK,
            summary="PIM notification rules cover privileged role activation events.",
            evidence=evidence_out,
            customer_summary="Activating powerful admin roles generates alerts.",
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="PIM activation alerts for non-GA privileged roles were not confirmed.",
        evidence=evidence_out,
        customer_summary="Confirm alerts fire when other admin roles are activated.",
    )

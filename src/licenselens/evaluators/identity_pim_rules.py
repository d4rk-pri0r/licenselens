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


def _parse_iso8601_duration_hours(value: Any) -> float | None:
    """Parse an ISO-8601 duration like PT8H / PT30M / PT0S into hours (None if unparsable)."""
    text = str(value or "").strip().upper()
    if not text.startswith("PT"):
        return None
    text = text[2:]
    total: float = 0.0
    number = ""
    for char in text:
        if char.isdigit() or char == ".":
            number += char
            continue
        if not number:
            return None
        if char == "H":
            total += float(number) * 60.0
        elif char == "M":
            total += float(number)
        elif char == "S":
            total += float(number) / 60.0
        else:
            return None
        number = ""
    if number:
        return None
    return total / 60.0


def _activation_expiration_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        r
        for r in rules
        if "expiration" in _rule_type(r) and "activation" in str(r.get("id") or "").lower()
    ]


def _activation_expiration_ok(rules: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    durations: list[str] = []
    if not rules:
        return False, durations
    required_found = False
    all_capped = True
    for rule in rules:
        durations.append(str(rule.get("maximumDuration") or ""))
        if not bool(rule.get("isExpirationRequired")):
            continue
        required_found = True
        hours = _parse_iso8601_duration_hours(rule.get("maximumDuration"))
        if hours is None or hours <= 0 or hours > 8:
            all_capped = False
    return required_found and all_capped, durations


def _activation_auth_context_ok(rules: list[dict[str, Any]]) -> tuple[bool, str | None]:
    claim: str | None = None
    ok = False
    for rule in rules:
        if "authenticationcontext" not in _rule_type(rule):
            continue
        if "activation" not in str(rule.get("id") or "").lower():
            continue
        claim = str(rule.get("claimValue") or "") or None
        if bool(rule.get("isEnabled")) and claim:
            ok = True
    return ok, claim


def _activation_justification_ok(rules: list[dict[str, Any]]) -> bool:
    for rule in rules:
        if "enablement" not in _rule_type(rule):
            continue
        if "activation" not in str(rule.get("id") or "").lower():
            continue
        enabled_rules = {
            str(item).lower() for item in (rule.get("enabledRules") or [])
        }
        if "justification" in enabled_rules:
            return True
    return False


def evaluate_pim_activation_controls(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """PIM activation guardrails: short duration, authentication context, justification."""
    del check

    if evidence.get("pim_policies_bundle_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="PIM role management policies could not be read: "
            + str(evidence["pim_policies_bundle_error"]),
            evidence={"error": str(evidence["pim_policies_bundle_error"])},
        )

    bundle = _pim_bundle(evidence)
    policies = list(bundle.get("policies") or [])
    all_rules: list[dict[str, Any]] = []
    for policy in policies:
        all_rules.extend(list(policy.get("rules") or []))

    expiration_rules = _activation_expiration_rules(all_rules)
    expiration_ok, durations = _activation_expiration_ok(expiration_rules)
    auth_context_ok, claim_value = _activation_auth_context_ok(all_rules)
    justification_ok = _activation_justification_ok(all_rules)

    evidence_out = {
        "policy_count": len(policies),
        "activation_rule_count": len(all_rules),
        "activation_maximum_durations": durations,
        "activation_duration_capped": expiration_ok,
        "auth_context_required": auth_context_ok,
        "auth_context_claim_value": claim_value,
        "justification_required": justification_ok,
    }

    if not all_rules:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "PIM role management policy rules were not available, so "
                "activation guardrails could not be verified."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not read your privileged-role activation settings, "
                "so please confirm the activation window, justification, and "
                "authentication-context requirements in the Entra portal."
            ),
        )

    missing: list[str] = []
    if not expiration_ok:
        missing.append("activation duration is not capped at 8 hours or less")
    if not auth_context_ok:
        missing.append("activation does not require an authentication context")
    if not justification_ok:
        missing.append("activation does not require justification")

    if not missing:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Privileged-role activation requires justification and an "
                "authentication context, and is capped to a short window."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Turning on a powerful admin role requires a written reason, "
                "the approved sign-in context, and expires quickly."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary="PIM activation guardrails are incomplete: " + "; ".join(missing) + ".",
        evidence=evidence_out,
        customer_summary=(
            "Some activation guardrails are missing, so an attacker with a "
            "stolen admin account can hold powerful access longer and with "
            "less traceability."
        ),
    )


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

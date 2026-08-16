"""Security defaults and access review evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus


def _enabled_ca_policies(policies: Any) -> tuple[int, int, int]:
    """Count enabled / report-only / disabled Conditional Access policies."""
    enabled = 0
    report_only = 0
    disabled = 0
    for policy in policies or []:
        if not isinstance(policy, dict):
            continue
        state = str(policy.get("state") or "").lower()
        if state == "enabled":
            enabled += 1
        elif state in {"enabledforreportingbutnotenforced", "reportonly"}:
            report_only += 1
        elif state == "disabled":
            disabled += 1
        else:
            # Unknown state: count as present-but-uncertain, not enforced.
            report_only += 1
    return enabled, report_only, disabled


def evaluate_security_defaults_on(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Security defaults enabled while the tenant is licensed for Conditional Access."""
    del check

    if evidence.get("security_defaults_policy_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Security defaults policy could not be read: "
            + str(evidence["security_defaults_policy_error"]),
            evidence={"error": str(evidence["security_defaults_policy_error"])},
        )

    policy = evidence.get("security_defaults_policy") or {}
    is_enabled = bool(policy.get("isEnabled")) if isinstance(policy, dict) else False

    evidence_out: dict[str, Any] = {
        "security_defaults_enabled": is_enabled,
        "baseline_protections_active": is_enabled,
        "policy_id": policy.get("id") if isinstance(policy, dict) else None,
    }

    if is_enabled:
        evidence_out["conditional_access_customization_unused"] = True
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Security defaults are enabled, providing baseline MFA protections "
                "and blocking legacy authentication. Licensed Conditional Access "
                "customization remains unused."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Security Defaults already includes baseline MFA protection and "
                "blocks outdated sign-in methods. Your plan also includes smarter "
                "sign-in rules you can customize, but that paid capability remains unused."
            ),
        )

    # Security defaults OFF means baseline protection must come from enforced CA
    # policies — a bare "confirm policies exist" caveat is not OK.
    evidence_out["conditional_access_customization_unused"] = None
    ca_policies = evidence.get("ca_policies")
    if ca_policies is None:
        evidence_out["ca_policy_count"] = None
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Security defaults are disabled and Conditional Access coverage "
                "could not be confirmed."
            ),
            evidence=evidence_out,
            customer_summary=(
                "The free Microsoft security defaults are not in use, but we could "
                "not verify that Conditional Access policies are actually configured. "
                "Confirm sign-in policies exist before treating this as covered."
            ),
        )
    enabled, report_only, disabled = _enabled_ca_policies(ca_policies)
    evidence_out["ca_policy_count"] = len(list(ca_policies or []))
    evidence_out["ca_enabled_count"] = enabled
    evidence_out["ca_report_only_count"] = report_only
    if enabled > 0:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Security defaults are disabled and Conditional Access is in use "
                f"({enabled} enabled polic"
                f"{'y' if enabled == 1 else 'ies'})."
            ),
            evidence=evidence_out,
            customer_summary=(
                "The free Microsoft security defaults are off, and your tenant is "
                "instead protected by customizable Conditional Access policies."
            ),
        )
    if report_only > 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Security defaults are disabled and Conditional Access policies "
                f"exist ({report_only} report-only, {disabled} disabled) but none "
                "are enforced."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Sign-in policies appear to be prepared but are not yet enforced "
                "(report-only or disabled). No baseline sign-in protection is active."
            ),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            "Security defaults are disabled and no Conditional Access policies "
            "were found — no baseline sign-in protection is active."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Neither the free Microsoft security defaults nor Conditional Access "
            "policies are protecting sign-ins right now."
        ),
    )


_PRIV_SCOPE_KEYWORDS: tuple[str, ...] = (
    "global admin",
    "privileged role",
    "privileged access",
    "admin role",
    "administrator role",
    "azure ad role",
    "entra role",
    "directory role",
    "highly privileged",
)


def _review_is_privileged_scoped(definition: dict[str, Any]) -> bool:
    """Whether an access review definition plausibly targets privileged roles."""
    from licenselens.collectors import privileged_roles as priv

    text = " ".join(str(definition.get(k) or "") for k in ("displayName", "description")).lower()
    if any(keyword in text for keyword in _PRIV_SCOPE_KEYWORDS):
        return True
    for display_name in priv.ROLE_DISPLAY_NAMES.values():
        if display_name.lower() in text:
            return True
    scope = definition.get("scope") or {}
    if not isinstance(scope, dict):
        return False
    for principal in scope.get("principalScopes") or []:
        if not isinstance(principal, dict):
            continue
        query = str(principal.get("query") or "").lower()
        if "rolemanagement" in query or "directoryrole" in query:
            return True
        for template_id in priv.PRIVILEGED_ROLE_TEMPLATE_IDS:
            if template_id.lower() in query:
                return True
    return False


def _review_is_recurring(definition: dict[str, Any]) -> bool:
    settings = definition.get("settings") or {}
    if not isinstance(settings, dict):
        return False
    recurrence = settings.get("recurrence") or {}
    return isinstance(recurrence, dict) and bool(recurrence)


def evaluate_access_reviews_unused(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Access reviews licensed but not configured."""
    del check

    if evidence.get("access_review_definitions_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Access review definitions could not be read: "
            + str(evidence["access_review_definitions_error"]),
            evidence={"error": str(evidence["access_review_definitions_error"])},
        )

    definitions = [
        d for d in evidence.get("access_review_definitions") or [] if isinstance(d, dict)
    ]
    count = len(definitions)

    privileged = [d for d in definitions if _review_is_privileged_scoped(d)]
    recurring = [d for d in definitions if _review_is_recurring(d)]
    privileged_recurring = [
        d for d in definitions if _review_is_privileged_scoped(d) and _review_is_recurring(d)
    ]

    evidence_out = {
        "definition_count": count,
        "definition_ids": [d.get("id") for d in definitions][:10],
        "privileged_scoped_count": len(privileged),
        "recurring_count": len(recurring),
        "privileged_recurring_count": len(privileged_recurring),
    }

    if count == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "No access review definitions were found. Access Reviews "
                "are included in the tenant's plan but have never been configured."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Your plan can periodically confirm who still needs powerful "
                "access and clean up old guest accounts. That process does not "
                "look set up yet."
            ),
        )

    if privileged_recurring:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Found {len(privileged_recurring)} recurring access review "
                "definition(s) covering privileged roles — the process is configured."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Periodic access reviews that cover powerful admin roles appear "
                "to be set up. Confirm the most recent round has completed successfully."
            ),
        )

    if privileged:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(privileged)} access review definition(s) target privileged "
                "roles, but none is configured to recur — reviews are not periodic."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Powerful admin roles are in scope for access reviews, but the "
                "reviews do not repeat on a schedule, so privilege can still accumulate."
            ),
        )

    if recurring:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(recurring)} recurring access review definition(s) exist, "
                "but none could be confirmed to cover privileged roles."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Periodic reviews appear to run, but we could not confirm they "
                "include your most powerful admin roles."
            ),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Found {count} access review definition(s), but none is confirmed to "
            "cover privileged roles on a recurring schedule."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Access reviews exist, but we could not confirm they periodically "
            "cover your most powerful admin roles."
        ),
    )


_COMPLETED_INSTANCE_STATUSES: frozenset[str] = frozenset({"completed", "applied"})


def _instances_by_definition(
    evidence: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    rows = evidence.get("access_review_instances")
    if not isinstance(rows, list):
        rows = [
            d
            for d in evidence.get("access_review_definitions") or []
            if isinstance(d, dict) and d.get("instances") is not None
        ]
    mapping: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        definition_id = str(row.get("id") or "")
        instances = row.get("instances")
        if definition_id and isinstance(instances, list):
            mapping[definition_id] = [i for i in instances if isinstance(i, dict)]
    return mapping


def evaluate_access_reviews_scope(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Access reviews cover privileged roles, recur, and have completed a round."""
    del check

    if evidence.get("access_review_definitions_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Access review definitions could not be read: "
            + str(evidence["access_review_definitions_error"]),
            evidence={"error": str(evidence["access_review_definitions_error"])},
        )
    if evidence.get("access_review_instances_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Access review instances could not be read: "
            + str(evidence["access_review_instances_error"]),
            evidence={"error": str(evidence["access_review_instances_error"])},
        )

    definitions = [
        d for d in evidence.get("access_review_definitions") or [] if isinstance(d, dict)
    ]
    instances_by_id = _instances_by_definition(evidence)

    privileged = [d for d in definitions if _review_is_privileged_scoped(d)]
    privileged_recurring = [d for d in privileged if _review_is_recurring(d)]
    completed_by_id = {
        definition_id: [
            i
            for i in instances
            if str(i.get("status") or "").lower() in _COMPLETED_INSTANCE_STATUSES
        ]
        for definition_id, instances in instances_by_id.items()
    }
    scoped_with_completed_rounds = [
        d for d in privileged_recurring if completed_by_id.get(str(d.get("id") or ""))
    ]

    evidence_out = {
        "definition_count": len(definitions),
        "privileged_scoped_count": len(privileged),
        "privileged_recurring_count": len(privileged_recurring),
        "definitions_with_completed_rounds": [
            str(d.get("id")) for d in scoped_with_completed_rounds
        ],
        "instance_count_by_definition": {
            str(definition_id): len(instances)
            for definition_id, instances in instances_by_id.items()
        },
    }

    if not definitions:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "No access review definitions were found, so privileged roles "
                "are not covered by recurring, executed reviews."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Periodic confirmation of powerful admin access does not look "
                "set up at all, so privilege can accumulate without review."
            ),
        )

    if not privileged:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"{len(definitions)} access review definition(s) exist, but "
                "none could be confirmed to cover privileged directory roles."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Your access reviews do not appear to include the powerful "
                "admin roles where stale access hurts most."
            ),
        )

    if not privileged_recurring:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(privileged)} privileged-scoped review definition(s) "
                "exist, but none is configured to recur — reviews run once."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Powerful admin roles are reviewed, but only as one-off "
                "exercises, so new privilege can still pile up between rounds."
            ),
        )

    if scoped_with_completed_rounds:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"{len(scoped_with_completed_rounds)} recurring privileged-role "
                "access review definition(s) have completed at least one round."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Your recurring privileged-role reviews have actually run to "
                "completion, so stale admin access is being caught."
            ),
        )

    ran_instances = any(
        bool(instances_by_id.get(str(d.get("id") or ""))) for d in privileged_recurring
    )
    if ran_instances:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(privileged_recurring)} recurring privileged-role review "
                "definition(s) exist with instances, but no completed round "
                "was found."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Privileged-role reviews are scheduled, but no round has "
                "finished yet — complete one so decisions are actually applied."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"{len(privileged_recurring)} recurring privileged-role review "
            "definition(s) exist, but no review instance has ever run."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Privileged-role reviews are configured on paper but have never "
            "executed, so nobody has actually re-confirmed admin access."
        ),
    )


def evaluate_entitlement_access_packages(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Entitlement Management access packages configured (lifecycle-governed access)."""
    del check

    if evidence.get("access_packages_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Entitlement access packages could not be read: "
            + str(evidence["access_packages_error"]),
            evidence={"error": str(evidence["access_packages_error"])},
        )

    packages = [p for p in evidence.get("access_packages") or [] if isinstance(p, dict)]
    count = len(packages)
    visible = [p for p in packages if not p.get("isHidden")]
    hidden = [p for p in packages if p.get("isHidden")]

    evidence_out = {
        "access_package_count": count,
        "visible_access_packages": len(visible),
        "hidden_access_packages": len(hidden),
        "access_package_names": [p.get("displayName") for p in packages][:10],
    }

    if count == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "No Entitlement Management access packages were found. Access "
                "packages are included in the tenant's plan but have never been "
                "configured."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Your plan can bundle access to apps, groups, and Teams into "
                "requestable packages with approvals and expiry. That "
                "lifecycle-governed access has not been set up yet."
            ),
        )

    if visible:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Found {count} Entitlement Management access "
                f"package(s) ({len(visible)} visible) — lifecycle-governed access "
                "is configured."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Requestable access packages for apps, groups, and Teams appear "
                "to be in place, so access can be granted with approval and expiry."
            ),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Found {count} access package(s), but all are hidden from "
            "requesters — access packages exist without being offered."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Access packages exist but are hidden from the people who would "
            "request them, so governed access is prepared but not yet in use."
        ),
    )

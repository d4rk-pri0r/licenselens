"""Security defaults and access review evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus


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

    if not is_enabled:
        evidence_out["conditional_access_customization_unused"] = None
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                "Security defaults are disabled, suggesting Conditional Access "
                "is being used instead of the free baseline."
            ),
            evidence=evidence_out,
            customer_summary=(
                "The free Microsoft security defaults are not in use, which is "
                "expected when you have Conditional Access licenses. Confirm "
                "that sign-in policies are actually configured."
            ),
        )

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

    definitions = list(evidence.get("access_review_definitions") or [])
    count = len(definitions)

    evidence_out = {
        "definition_count": count,
        "definition_ids": [d.get("id") for d in definitions if isinstance(d, dict)][:10],
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

    return Evaluation(
        status=FindingStatus.OK,
        summary=f"Found {count} access review definition(s) — the process is configured.",
        evidence=evidence_out,
        customer_summary=(
            "Periodic access reviews appear to be set up. Confirm the most "
            "recent round has completed successfully."
        ),
    )

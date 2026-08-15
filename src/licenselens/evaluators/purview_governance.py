"""Direct Purview data-protection and governance evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.collectors.exchange_models import PolicyItem
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.purview_lib import (
    SurfaceRead,
    denied,
    direct_meta,
    read_surface,
    unreadable,
)
from licenselens.models import CheckDefinition, FindingStatus

_AUTO_LABELING_MARKERS: Final = frozenset(
    {"DefaultLabelId", "DefaultLabel", "AutoLabeling", "AutoApply"}
)


def evaluate_pur_sensitivity_labels_published(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    labels = read_surface(evidence, "sensitivity_labels")
    policies = read_surface(evidence, "label_policies")
    if labels.state is SurfaceRead.DENIED or policies.state is SurfaceRead.DENIED:
        return denied(
            "sensitivity_labels",
            "We could not confirm whether sensitivity labels are published to users.",
        )
    if labels.state is SurfaceRead.UNREADABLE or policies.state is SurfaceRead.UNREADABLE:
        return unreadable(
            "sensitivity_labels",
            "We could not read sensitivity-label publication state.",
        )
    defined = len(labels.items)
    published = any(item.enabled is not False for item in policies.items)
    evidence_out = {
        "adapter": labels.adapter or policies.adapter,
        "sensitivity_labels": defined,
        "published_label_policies": len(policies.items),
        "published": published,
        "absent": defined == 0,
        "unpublished": defined > 0 and not published,
    }
    if defined and published:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"{defined} sensitivity label(s) are defined and published to users.",
            evidence=evidence_out,
            customer_summary="Sensitivity labels are available for people to apply to content.",
            **direct_meta(),
        )
    if defined:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Sensitivity labels exist but are not published to any users.",
            evidence=evidence_out,
            customer_summary=(
                "Labels are defined but never published, so nobody can apply them. "
                "Publish a label policy to make them available."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No sensitivity labels are defined.",
        evidence=evidence_out,
        customer_summary=(
            "No sensitivity labels exist to classify documents and email. "
            "Create and publish at least a basic label set."
        ),
        **direct_meta(),
    )


def evaluate_pur_sensitivity_auto_labeling(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policies = read_surface(evidence, "label_policies")
    if policies.state is SurfaceRead.DENIED:
        return denied(
            "label_policies",
            "We could not confirm whether auto-labeling is configured.",
        )
    if policies.state is SurfaceRead.UNREADABLE:
        return unreadable(
            "label_policies",
            "We could not read sensitivity auto-labeling state.",
        )
    auto = any(_has_auto_marker(item) for item in policies.items if item.enabled is not False)
    evidence_out = {
        "adapter": policies.adapter,
        "label_policies": len(policies.items),
        "auto_labeling": auto,
        "absent": len(policies.items) == 0,
    }
    if auto:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Auto-labeling is configured for sensitivity labels.",
            evidence=evidence_out,
            customer_summary="Sensitive content is labeled automatically based on your rules.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No auto-labeling policy is configured.",
        evidence=evidence_out,
        customer_summary=(
            "Content must be labeled by hand. Configure auto-labeling so sensitive "
            "content is classified consistently."
        ),
        **direct_meta(),
    )


def evaluate_pur_retention_policy_coverage(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policies = read_surface(evidence, "retention_policies")
    rules = read_surface(evidence, "retention_rules")
    if policies.state is SurfaceRead.DENIED or rules.state is SurfaceRead.DENIED:
        return denied(
            "retention_policies",
            "We could not confirm whether retention policies cover your workloads.",
        )
    if policies.state is SurfaceRead.UNREADABLE or rules.state is SurfaceRead.UNREADABLE:
        return unreadable(
            "retention_policies",
            "We could not read retention policy coverage.",
        )
    count = len(policies.items)
    rule_count = len(rules.items)
    evidence_out = {
        "adapter": policies.adapter or rules.adapter,
        "retention_policies": count,
        "retention_rules": rule_count,
        "absent": count == 0,
    }
    if count and rule_count:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"{count} retention polic(y/ies) with {rule_count} rule(s) are configured.",
            evidence=evidence_out,
            customer_summary=(
                "Content retention rules are in place. Confirm durations match your "
                "legal or regulatory requirements."
            ),
            **direct_meta(),
        )
    if count:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Retention policies exist but no retention rules are configured.",
            evidence=evidence_out,
            customer_summary=(
                "Retention policies without rules do nothing yet. Add retention rules "
                "so content is kept or deleted on schedule."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No retention policies are configured.",
        evidence=evidence_out,
        customer_summary=(
            "Nothing governs how long content is kept. Create retention policies "
            "for email and files to meet legal or regulatory needs."
        ),
        **direct_meta(),
    )


def _has_auto_marker(item: PolicyItem) -> bool:
    return any(name in item.properties for name in _AUTO_LABELING_MARKERS)

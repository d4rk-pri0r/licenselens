"""Sentinel workload evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus


def evaluate_sen_analytics_coverage(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess enabled Sentinel analytics rule density and tactic coverage."""
    del check
    if evidence.get("sentinel_workspace_missing"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Sentinel workspace was not provided. Pass --workspace-resource-id "
                "or subscription/resource-group/workspace-name to evaluate analytics rules."
            ),
            evidence={"hint": "workspace_required"},
            customer_summary=(
                "We found Sentinel licensing signals, but need the security workspace "
                "location to check whether alarms are turned on."
            ),
        )

    rules = dict(evidence.get("sentinel_rules") or {})
    if evidence.get("sentinel_rules_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Could not read Sentinel analytics rules: {evidence['sentinel_rules_error']}",
            evidence=rules,
            customer_summary=(
                "We could not read detection rules in your security workspace. "
                "This is often missing Azure permissions on the workspace."
            ),
        )

    enabled = int(rules.get("enabled_scheduled_or_nrt") or rules.get("enabled_rules") or 0)
    total = int(rules.get("total_rules") or 0)
    tactics = int(rules.get("tactic_count") or 0)
    evidence_out = dict(rules)

    if total == 0 and enabled == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Sentinel analytics rules were found in the workspace.",
            evidence=evidence_out,
            customer_summary=(
                "Your security command center appears empty — few or no detection "
                "alarms are configured."
            ),
        )

    if enabled == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"Found {total} analytics rule(s) but none are enabled.",
            evidence=evidence_out,
            customer_summary=(
                "Detection rules exist but are turned off, so the workspace is not "
                "actively watching for threats."
            ),
        )

    if enabled >= 10 and tactics >= 3:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Sentinel analytics coverage looks healthy: {enabled} enabled "
                f"scheduled/NRT rule(s) across {tactics} MITRE tactic(s)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Your security workspace has a solid set of alarms turned on across "
                "multiple attack stages."
            ),
        )

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Thin Sentinel analytics coverage: {enabled} enabled scheduled/NRT "
            f"rule(s), {tactics} tactic(s) (total rules={total})."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Some detection alarms are on, but coverage still looks light for a "
            "paid security command center."
        ),
    )


def evaluate_sen_ueba(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess Sentinel UEBA / entity analytics enablement."""
    del check
    if evidence.get("sentinel_workspace_missing"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Sentinel workspace was not provided. Pass --workspace-resource-id "
                "to evaluate UEBA / entity analytics."
            ),
            evidence={"hint": "workspace_required"},
            customer_summary=(
                "We need the security workspace location to check behavior analytics."
            ),
        )

    ueba = dict(evidence.get("sentinel_ueba") or {})
    if evidence.get("sentinel_ueba_error") and not ueba:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Could not read Sentinel settings: {evidence['sentinel_ueba_error']}",
            evidence=ueba,
            customer_summary=("We could not verify behavior analytics settings on the workspace."),
        )

    if (
        ueba.get("settings_error")
        and ueba.get("ueba_enabled") is False
        and not ueba.get("raw_entity_present")
    ):
        # Could not read settings — distinguish from explicitly off
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=f"Sentinel settings read failed: {ueba.get('settings_error')}",
            evidence=ueba,
            customer_summary=(
                "Behavior analytics status could not be verified (permissions or API)."
            ),
        )

    if ueba.get("ueba_enabled"):
        return Evaluation(
            status=FindingStatus.OK,
            summary="Sentinel UEBA / entity analytics appears enabled.",
            evidence=ueba,
            customer_summary=(
                "Behavior-based detection looks turned on in your security workspace."
            ),
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary="Sentinel UEBA / entity analytics does not appear enabled.",
        evidence=ueba,
        customer_summary=(
            "Behavior analytics that learn normal patterns for people and devices "
            "still looks switched off."
        ),
    )

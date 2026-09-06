"""Protective-plan assignment evaluator (counts only)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.license_assignment import PROTECTIVE_CAPABILITIES
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_OK_RATIO = 0.85
_GAP_RATIO = 0.5


def evaluate_protective_plan_assignment(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    assignment = evidence.get("license_assignment")
    if not isinstance(assignment, dict):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Protective-plan assignment counts were not available.",
            evidence={},
            customer_summary="We could not count how many users have protective plans assigned.",
        )
    enabled = assignment.get("enabled_member_users")
    by_cap = assignment.get("by_capability") or {}
    if not isinstance(by_cap, dict) or enabled is None:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Protective-plan assignment counts were not available.",
            evidence={"license_assignment": assignment},
            customer_summary="We could not count how many users have protective plans assigned.",
        )
    try:
        enabled_i = int(enabled)
    except (TypeError, ValueError):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Protective-plan assignment counts were not available.",
            evidence={"license_assignment": assignment},
            customer_summary="We could not count how many users have protective plans assigned.",
        )
    if enabled_i <= 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No enabled member users were reported, so assignment coverage is unresolved.",
            evidence={"enabled_member_users": enabled_i, "by_capability": by_cap},
            customer_summary="We could not determine the user population for plan assignment.",
            confidence=Confidence.MEDIUM,
        )

    owned = {str(item) for item in (evidence.get("owned_capabilities") or [])}
    rows: list[dict[str, Any]] = []
    worst = 1.0
    any_row = False
    for cap_id in PROTECTIVE_CAPABILITIES:
        if cap_id not in owned:
            continue
        raw = by_cap.get(cap_id) if isinstance(by_cap.get(cap_id), dict) else {}
        assigned = raw.get("assigned_users")
        method = str(raw.get("method") or "unavailable")
        if assigned is None or method == "unavailable":
            rows.append({"capability_id": cap_id, "assigned_users": None, "method": method})
            continue
        try:
            assigned_i = int(assigned)
        except (TypeError, ValueError):
            rows.append({"capability_id": cap_id, "assigned_users": None, "method": method})
            continue
        ratio = assigned_i / enabled_i
        any_row = True
        worst = min(worst, ratio)
        rows.append(
            {
                "capability_id": cap_id,
                "assigned_users": assigned_i,
                "enabled_member_users": enabled_i,
                "ratio": ratio,
                "method": method,
            }
        )

    evidence_out = {
        "enabled_member_users": enabled_i,
        "capabilities": rows,
    }
    if not any_row:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Protective-plan assignment counts were not available.",
            evidence=evidence_out,
            customer_summary="We could not count how many users have protective plans assigned.",
        )
    if worst < _GAP_RATIO:
        status = FindingStatus.GAP
        summary = (
            f"Protective plans are assigned to fewer than half of enabled member users "
            f"(lowest share {worst * 100:.0f}% of {enabled_i})."
        )
        customer = "Protective plans are assigned to only some users."
    elif worst < _OK_RATIO:
        status = FindingStatus.PARTIAL
        summary = (
            f"Protective plans are assigned to some enabled member users "
            f"(lowest share {worst * 100:.0f}% of {enabled_i})."
        )
        customer = "Protective plans are assigned to some users, but not most."
    else:
        status = FindingStatus.OK
        summary = (
            f"Protective plans are assigned to most enabled member users "
            f"(lowest share {worst * 100:.0f}% of {enabled_i})."
        )
        assigned_n = int(round(worst * enabled_i))
        customer = f"Protective plans are assigned to {assigned_n} of {enabled_i} users."
    return Evaluation(
        status=status,
        summary=summary,
        evidence=evidence_out,
        customer_summary=customer,
        confidence=Confidence.HIGH,
        data_sources=["graph.users.$count"],
    )

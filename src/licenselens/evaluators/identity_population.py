"""Annotate risk-based findings with Identity Protection assignment population."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation


def annotate_protected_population(result: Evaluation, evidence: dict[str, Any]) -> Evaluation:
    """Attach assignment population without changing status."""
    assignment = evidence.get("license_assignment")
    if not isinstance(assignment, dict):
        return result
    enabled = assignment.get("enabled_member_users")
    by_cap = assignment.get("by_capability") or {}
    row = by_cap.get("identity_protection") if isinstance(by_cap, dict) else None
    if not isinstance(row, dict) or enabled is None:
        return result
    assigned = row.get("assigned_users")
    if assigned is None:
        return result
    try:
        assigned_i = int(assigned)
        enabled_i = int(enabled)
    except (TypeError, ValueError):
        return result
    if enabled_i <= 0 or assigned_i >= enabled_i:
        return result
    result.evidence["protected_population"] = {
        "assigned_users": assigned_i,
        "enabled_member_users": enabled_i,
    }
    note = (
        "Risk-based policies only protect users with an Entra ID P2 plan assigned: "
        f"{assigned_i} of {enabled_i}."
    )
    if note not in result.limitations:
        result.limitations.append(note)
    return result

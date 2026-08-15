"""Intune compliance policy assignment and noncompliance-action evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.endpoint_lib import (
    compliance_policies,
    direct_meta,
    intune_bundle,
    managed_devices,
    surface_error,
    unavailable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def _platform_matches(platform: str, policy_platforms: str) -> bool:
    lowered = platform.lower()
    tokens = policy_platforms.lower()
    return lowered in tokens or tokens in lowered


def _uncovered_platforms(
    devices: list[dict[str, Any]],
    assigned: list[dict[str, Any]],
) -> list[str]:
    device_platforms = {
        str(d.get("operatingSystem") or "") for d in devices if d.get("operatingSystem")
    }
    covered: set[str] = set()
    for policy in assigned:
        platforms = str(policy.get("platforms") or "").lower()
        for platform in device_platforms:
            if _platform_matches(platform, platforms):
                covered.add(platform)
    return sorted(device_platforms - covered)


def evaluate_endpoint_compliance_policy_assigned(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Compliance policies exist, are assigned, and cover managed-device platforms."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "compliance_policies")
    if error:
        return unavailable(
            "Intune compliance policies could not be read; treated as unresolved.",
            surface="compliance_policies",
            customer_summary="We could not confirm whether device-compliance policies exist.",
        )
    policies = compliance_policies(bundle)
    evidence_out = {
        "compliance_policy_count": len(policies),
        "assigned_count": sum(1 for p in policies if p.get("assigned")),
    }
    if not policies:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Intune device compliance policies are defined.",
            evidence=evidence_out,
            customer_summary=(
                "You appear to pay for device management, but no compliance policies "
                "are configured, so unhealthy devices are not being detected."
            ),
            **direct_meta(),
        )
    if any(p.get("assignments_error") for p in policies):
        evidence_out["assignment_readable"] = False
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(policies)} compliance policy(ies) defined, but assignment "
                "details could not be read."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Compliance policies exist, but we could not confirm they are assigned to users."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=[
                "Policy assignments were not readable; verify in the Intune admin center."
            ],
        )
    assigned = [p for p in policies if p.get("assigned")]
    evidence_out["assigned_count"] = len(assigned)
    if not assigned:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"{len(policies)} compliance policy(ies) defined but none are assigned.",
            evidence=evidence_out,
            customer_summary=(
                "Compliance policies exist but are not assigned, so they are not "
                "enforcing anything."
            ),
            **direct_meta(),
        )
    uncovered = _uncovered_platforms(managed_devices(bundle), assigned)
    evidence_out["uncovered_platforms"] = uncovered
    if uncovered:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(assigned)} assigned compliance policy(ies), but some managed "
                f"device platforms are uncovered: {', '.join(sorted(uncovered))}."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Compliance is assigned, but some device platforms have no matching policy."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["Platform coverage is incomplete for managed devices."],
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"{len(assigned)} compliance policy(ies) assigned and covering managed platforms.",
        evidence=evidence_out,
        customer_summary="Device compliance policies are defined and assigned.",
        **direct_meta(),
    )


def evaluate_endpoint_compliance_noncompliance_action(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Compliance policies carry a noncompliance action (notify/block)."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "compliance_policies")
    if error:
        return unavailable(
            "Intune compliance policies could not be read; treated as unresolved.",
            surface="compliance_policies",
            customer_summary="We could not confirm noncompliance actions.",
        )
    policies = compliance_policies(bundle)
    evidence_out = {"compliance_policy_count": len(policies)}
    if not policies:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No compliance policies exist to carry a noncompliance action.",
            evidence=evidence_out,
            customer_summary=(
                "No compliance policies are configured, so noncompliance is not acted on."
            ),
            **direct_meta(),
        )
    if any(p.get("noncompliance_actions_error") for p in policies):
        evidence_out["noncompliance_action_readable"] = False
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{len(policies)} compliance policy(ies) defined, but noncompliance "
                "action details could not be read."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not confirm what happens when a device falls out of compliance."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=[
                "Noncompliance actions were not readable; verify in the Intune admin center."
            ],
        )
    with_action = [p for p in policies if p.get("has_noncompliance_action")]
    evidence_out["policies_with_action"] = len(with_action)
    if not with_action:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"{len(policies)} compliance policy(ies) have no noncompliance action configured."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Compliance is checked, but nothing happens when a device falls out of compliance."
            ),
            **direct_meta(),
        )
    if len(with_action) < len(policies):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Only {len(with_action)} of {len(policies)} compliance policy(ies) "
                "configure a noncompliance action."
            ),
            evidence=evidence_out,
            customer_summary="Some compliance policies do not act on noncompliance.",
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["Not every compliance policy configures a noncompliance action."],
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"All {len(policies)} compliance policy(ies) configure a noncompliance action.",
        evidence=evidence_out,
        customer_summary="Falling out of compliance triggers an action.",
        **direct_meta(),
    )

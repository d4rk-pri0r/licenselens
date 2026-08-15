"""Manual-only identity checks that cannot be proven from Graph alone."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_idprotect_notify_high_risk(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check, evidence
    return Evaluation(
        status=FindingStatus.SKIPPED,
        summary=(
            "High-risk user admin notifications are portal-configured and not "
            "exposed as a complete Graph control for automated proof."
        ),
        evidence={"manual": True, "evaluation_mode": "manual"},
        customer_summary=(
            "Ask IT to confirm Identity Protection emails high-risk user alerts "
            "to a monitored security mailbox."
        ),
        confidence=Confidence.LOW,
        limitations=[
            "Manual verification required in Microsoft Entra ID Protection notifications."
        ],
    )


def evaluate_logs_to_soc(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check, evidence
    return Evaluation(
        status=FindingStatus.SKIPPED,
        summary=(
            "Centralized Entra sign-in/audit log shipping to a SOC is environment-specific "
            "and requires manual or SIEM-side verification."
        ),
        evidence={"manual": True, "evaluation_mode": "manual"},
        customer_summary=(
            "Confirm Entra sign-in and audit logs reach your security monitoring platform."
        ),
        confidence=Confidence.LOW,
        limitations=["Manual verification required with your SOC / SIEM team."],
    )


def evaluate_ai_agents_risky_block(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policies = list(evidence.get("ca_policies") or [])
    hits = []
    for policy in policies:
        blob = str(policy).lower()
        if "agent" in blob and ("risk" in blob or "block" in blob):
            hits.append(policy.get("displayName") or policy.get("id"))
    evidence_out = {"candidate_policies": hits, "manual_fallback": not bool(hits)}
    if hits:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Found Conditional Access policies that may address risky AI agents; "
                "confirm grant controls target agent risk specifically."
            ),
            evidence=evidence_out,
            customer_summary=(
                "There may be AI-agent protections, but they need a specialist review."
            ),
            confidence=Confidence.LOW,
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No Conditional Access policy clearly blocks risky AI agents.",
        evidence=evidence_out,
        customer_summary=(
            "We did not find an automated block for risky AI agents. Confirm in Entra "
            "whether agent risk controls are available and enforced for your tenant."
        ),
        confidence=Confidence.LOW,
        limitations=["AI agent risk controls vary by cloud and license; treat this as advisory."],
    )

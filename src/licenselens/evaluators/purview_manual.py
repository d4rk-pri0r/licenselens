"""Manual-only Purview governance checks (portal-configured, not readable)."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def _manual(summary: str, customer: str, limitation: str) -> Evaluation:
    return Evaluation(
        status=FindingStatus.SKIPPED,
        summary=summary,
        evidence={"manual": True, "evaluation_mode": "manual"},
        customer_summary=customer,
        confidence=Confidence.LOW,
        limitations=[limitation],
    )


def evaluate_pur_insider_risk_readiness(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check, evidence
    return _manual(
        "Insider risk policies and analytics are portal-configured and not "
        "automatically readable here.",
        "Confirm an insider risk policy is created, scoped, and analytics is enabled.",
        "Manual verification required in Microsoft Purview Insider Risk Management.",
    )


def evaluate_pur_communication_compliance_readiness(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check, evidence
    return _manual(
        "Communication compliance policies are portal-configured and not "
        "automatically readable here.",
        "Confirm communication compliance policies cover the channels that matter.",
        "Manual verification required in Microsoft Purview Communication Compliance.",
    )


def evaluate_pur_ediscovery_readiness(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check, evidence
    return _manual(
        "eDiscovery cases and holds are portal-configured and not automatically readable here.",
        "Confirm eDiscovery administrators and hold workflows are configured.",
        "Manual verification required in Microsoft Purview eDiscovery.",
    )

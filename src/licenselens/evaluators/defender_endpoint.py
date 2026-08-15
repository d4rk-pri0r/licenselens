"""Defender for Endpoint evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_mde_onboard_gap(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Compare MDE licensed units vs onboarded machines."""
    del check
    summary = dict(evidence.get("mde_summary") or {})
    licensed = summary.get("licensed_units")
    onboarded = summary.get("onboarded_machines")
    truncated = bool(summary.get("truncated"))

    if onboarded is None:
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Defender for Endpoint machine inventory was not available.",
            evidence=summary,
            customer_summary=(
                "We could not read device enrollment numbers for advanced PC "
                "protection. This is often a missing API permission."
            ),
        )

    onboarded_i = int(onboarded)
    evidence_out = {
        **summary,
        "coverage_ratio": (
            (onboarded_i / int(licensed)) if licensed and int(licensed) > 0 else None
        ),
    }
    sources = ["mde.api.machines", "graph.subscribedSkus"]
    conf = Confidence.MEDIUM if truncated else Confidence.HIGH
    limits: list[str] = []
    if truncated:
        limits.append("MDE machine inventory pagination was truncated.")

    if licensed is None or int(licensed) <= 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Found {onboarded_i} Defender for Endpoint machine(s), but could "
                "not determine licensed unit count from SKUs."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Devices are enrolled in advanced protection, but we could not "
                "compare that number to purchased seats automatically."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=sources,
            limitations=limits,
        )

    licensed_i = int(licensed)
    ratio = onboarded_i / licensed_i if licensed_i else 0.0
    evidence_out["coverage_ratio"] = ratio

    if ratio >= 0.85 and not truncated:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Defender for Endpoint coverage looks healthy: "
                f"{onboarded_i} onboarded vs ~{licensed_i} licensed units "
                f"({ratio * 100:.0f}%)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Most paid device-protection seats appear matched by enrolled devices."
            ),
            confidence=conf,
            data_sources=sources,
            limitations=limits,
        )

    if ratio >= 0.5:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Partial Defender for Endpoint onboarding: {onboarded_i} onboarded "
                f"vs ~{licensed_i} licensed units ({ratio * 100:.0f}%)."
                + (" Machine count may be truncated." if truncated else "")
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some PCs are enrolled in advanced protection, but a noticeable "
                "share of paid seats still look unused."
            ),
            confidence=conf,
            data_sources=sources,
            limitations=limits,
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"Large Defender for Endpoint onboarding gap: {onboarded_i} onboarded "
            f"vs ~{licensed_i} licensed units ({ratio * 100:.0f}%)."
            + (" Machine count may be truncated." if truncated else "")
        ),
        evidence=evidence_out,
        customer_summary=(
            "You appear to pay for advanced device protection on many seats, but "
            "relatively few devices are enrolled."
        ),
        confidence=conf,
        data_sources=sources,
        limitations=limits,
    )

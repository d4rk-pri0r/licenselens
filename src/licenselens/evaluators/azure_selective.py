"""Selective-Azure evaluators (Sentinel-adjacent Defender for Cloud boundary).

Only entitlement-linked Defender for Cloud plan pricing is assessed directly.
Generic Azure CSPM is explicitly out of scope and reported as manual.
"""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def _as_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def evaluate_az_defender_plan_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    if evidence.get("defender_for_cloud_pricings_error") and not evidence.get(
        "defender_for_cloud_pricings"
    ):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary=(
                "Could not read Defender for Cloud plan pricing: "
                f"{evidence['defender_for_cloud_pricings_error']}"
            ),
            evidence={"error": evidence["defender_for_cloud_pricings_error"]},
            customer_summary=(
                "We could not verify which Defender for Cloud plans are enabled "
                "(subscription permissions or missing subscription context)."
            ),
        )

    pricings = _as_dict(evidence.get("defender_for_cloud_pricings"))
    standard = list(pricings.get("standard_plans") or [])
    evidence_out = dict(pricings)

    if not standard:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Defender for Cloud plan is enabled at the Standard tier.",
            evidence=evidence_out,
            customer_summary=(
                "Your paid cloud protection appears to be at the free tier, so "
                "fewer alerts and hardening recommendations are available."
            ),
        )

    return Evaluation(
        status=FindingStatus.OK,
        summary=(
            f"Defender for Cloud is enabled for {len(standard)} plan(s): "
            + ", ".join(standard)
            + "."
        ),
        evidence=evidence_out,
        customer_summary=("Your cloud protection plan is turned on for the subscription."),
    )


def evaluate_az_cspm_out_of_scope(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check, evidence
    return Evaluation(
        status=FindingStatus.SKIPPED,
        summary=(
            "Generic Azure CSPM posture (VMs, storage, SQL, networking) is out of "
            "scope for this assessment; only entitlement-linked Sentinel and "
            "Defender for Cloud plan settings are evaluated here."
        ),
        evidence={"manual": True, "evaluation_mode": "manual"},
        customer_summary=(
            "Review and remediate Azure resource posture recommendations in "
            "Microsoft Defender for Cloud."
        ),
        confidence=Confidence.LOW,
        limitations=[
            "Generic Azure CSPM is intentionally unsupported; verify in Defender for Cloud."
        ],
    )

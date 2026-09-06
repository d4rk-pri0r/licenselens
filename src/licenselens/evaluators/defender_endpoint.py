"""Defender for Endpoint evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_mde_onboard_gap(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Report Defender for Endpoint onboarding against an eligible device population.

    Methodology (§6 of the product-maturity goal): a comparison of *licensed
    seats* to *onboarded machines* is **not** endpoint coverage. License count
    does not represent the device population unless Microsoft licensing
    semantics explicitly justify it. LicenseLens therefore:

    - reports the *observed* onboarded machine count as the primary observation;
    - computes genuine ``coverage_ratio`` only when an authoritative eligible
      device inventory (``eligible_devices``) is supplied;
    - otherwise labels the licensed-seat comparison as a *licensing-leverage*
      proxy signal and **never** reaches ``OK``/``coverage`` on it.

    A machine inventory that matches licenses is an efficiency signal, not
    proof that an eligible device population is protected. When the licensed
    seats far exceed onboarded machines, that is a real signal of unrealized
    licensing, but it must be worded as such — not as a health verdict.
    """
    del check
    summary = dict(evidence.get("mde_summary") or {})
    licensed = summary.get("licensed_units")
    onboarded = summary.get("onboarded_machines")
    recon = dict(evidence.get("device_reconciliation") or {})
    if recon.get("available") is False:
        recon = {}
    eligible = summary.get("eligible_devices")
    truncated = bool(summary.get("truncated")) or bool(recon.get("truncated"))
    denominator_source = None
    if recon and recon.get("intune_active") is not None and "intune_active" in recon:
        eligible = recon.get("intune_active")
        denominator_source = "intune_managed_active_30d"
        truncated = bool(recon.get("truncated")) or truncated

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
    evidence_out = {**summary}
    sources = ["mde.api.machines"]
    conf = Confidence.MEDIUM if truncated else Confidence.HIGH
    limits: list[str] = []
    if truncated:
        limits.append("MDE machine inventory pagination was truncated.")

    if eligible is not None:
        eligible_i = int(eligible)
        if eligible_i <= 0:
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    f"Found {onboarded_i} onboarded Defender for Endpoint machine(s), "
                    "but the eligible device population reported was empty or zero, "
                    "so coverage could not be computed."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "We could not determine which devices should be onboarded, so "
                    "we cannot confirm advanced protection coverage."
                ),
                confidence=Confidence.MEDIUM,
                data_sources=sources,
                limitations=[
                    "An authoritative eligible-device inventory was present but "
                    "reported zero devices; coverage is unresolved."
                ],
            )
        ratio = onboarded_i / eligible_i
        evidence_out["coverage_ratio"] = ratio
        evidence_out["eligible_devices"] = eligible_i
        if denominator_source:
            evidence_out["denominator_source"] = denominator_source
            limits.append(
                "Denominator is the Intune-managed active population; unmanaged "
                "devices and servers outside Intune are not counted."
            )
        if ratio >= 0.85 and not truncated:
            return Evaluation(
                status=FindingStatus.OK,
                summary=(
                    f"Defender for Endpoint coverage is high: {onboarded_i} of "
                    f"{eligible_i} eligible device(s) are onboarded "
                    f"({ratio * 100:.0f}%)."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "Most devices in the eligible population are enrolled in "
                    "advanced device protection."
                ),
                confidence=conf,
                data_sources=sources,
                limitations=limits,
            )
        if ratio >= 0.5:
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    f"Partial Defender for Endpoint onboarding: {onboarded_i} of "
                    f"{eligible_i} eligible device(s) onboarded "
                    f"({ratio * 100:.0f}%)."
                    + (" Device count may be truncated." if truncated else "")
                ),
                evidence=evidence_out,
                customer_summary=(
                    "Some devices in the eligible population are onboarded to "
                    "advanced protection, but a meaningful share may be missing."
                ),
                confidence=conf,
                data_sources=sources,
                limitations=limits,
            )
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Large Defender for Endpoint onboarding gap: {onboarded_i} of "
                f"{eligible_i} eligible device(s) onboarded ({ratio * 100:.0f}%)."
                + (" Device count may be truncated." if truncated else "")
            ),
            evidence=evidence_out,
            customer_summary=(
                "A large share of the eligible device population is not onboarded "
                "to advanced device protection."
            ),
            confidence=conf,
            data_sources=sources,
            limitations=limits,
        )

    leverage_limits = list(limits)
    leverage_limits.append(
        "Coverage is reported against purchased license seats, not an authoritative "
        "device inventory; license counts do not necessarily equal the device "
        "population, so this is a licensing-leverage signal, not proven device "
        "coverage. Verify actual eligible devices in the Defender portal."
    )
    evidence_out["proxy"] = True
    evidence_sources = list(sources) + ["graph.subscribedSkus (proxy licensing signal)"]

    if licensed is None or int(licensed) <= 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Observed {onboarded_i} onboarded Defender for Endpoint machine(s). "
                "Could not compare to purchased seats, and no authoritative device "
                "population was available."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Devices are enrolled in advanced protection. Without an eligible "
                "device inventory we cannot confirm whether coverage is complete."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=evidence_sources,
            limitations=leverage_limits,
        )

    licensed_i = int(licensed)
    ratio = onboarded_i / licensed_i if licensed_i else 0.0
    evidence_out["coverage_ratio"] = ratio
    evidence_out["licensed_units"] = licensed_i

    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Observed {onboarded_i} onboarded Defender for Endpoint machine(s) vs "
            f"~{licensed_i} purchased seats ({ratio * 100:.0f}% of seats). "
            "This is a licensing-leverage signal and is not treated as device "
            "coverage; an eligible device inventory is required to confirm coverage."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Without an authoritative eligible-device inventory we cannot confirm "
            "how much of the intended device population is actually protected."
        ),
        confidence=Confidence.LOW,
        data_sources=evidence_sources,
        limitations=leverage_limits,
    )

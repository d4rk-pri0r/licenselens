"""Intune enrollment coverage evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.endpoint_lib import (
    intune_bundle,
    managed_devices,
    surface_error,
    unavailable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_endpoint_enrollment_coverage(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Report Intune enrollment against an authoritative managed-device population.

    Methodology (§6 of the product-maturity goal): licensed Intune seats do not
    equal the device population. This evaluator therefore reports the observed
    number of managed devices directly, and only computes genuine
    ``coverage_ratio`` when an authoritative eligible/expected device inventory
    (``eligible_devices``) is supplied. When device reconciliation supplies the
    joined population, coverage is ``entra_matched_intune / entra_active`` —
    Entra-active devices matched as Intune-managed — never the raw, unmatched
    managed-device count over the reconciliation denominator. Without either,
    the licensed-seat comparison is a proxy licensing-leverage signal that can
    never reach OK.
    """
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "managed_devices")
    if error:
        return unavailable(
            "Intune device enrollment could not be read; treated as unresolved.",
            surface="managed_devices",
            customer_summary="We could not confirm how many devices are enrolled.",
        )
    devices = managed_devices(bundle)
    licensed = (bundle or {}).get("licensed_units")
    recon = dict(evidence.get("device_reconciliation") or {})
    if recon.get("available") is False:
        recon = {}
    eligible = (bundle or {}).get("eligible_devices")
    truncated = bool((bundle or {}).get("truncated")) or bool(recon.get("truncated"))
    denominator_source = None
    matched: int | None = None
    if (
        recon
        and recon.get("entra_active") is not None
        and recon.get("entra_matched_intune") is not None
    ):
        eligible = recon.get("entra_active")
        matched = int(recon["entra_matched_intune"])
        denominator_source = "entra_devices_active_30d"
        truncated = bool(recon.get("truncated")) or truncated
    count = len(devices)
    numerator = count if matched is None else matched
    evidence_out = {
        "managed_device_count": count,
        "licensed_units": licensed,
        "truncated": truncated,
    }
    if matched is not None:
        evidence_out["matched_devices"] = matched
        unmatched = int(recon.get("unmatched_ids") or 0)
        if unmatched > 0:
            evidence_out["unmatched_ids"] = unmatched

    def _coverage_verdict() -> Evaluation:
        eligible_i = int(eligible)
        if eligible_i <= 0:
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    f"Observed {count} managed device(s), but the eligible device "
                    "population reported was empty or zero, so coverage is unresolved."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "We could not determine which devices should be managed, so we "
                    "cannot confirm enrollment coverage."
                ),
                confidence=Confidence.MEDIUM,
                data_sources=["graph.deviceManagement"],
                limitations=[
                    "An authoritative eligible-device inventory was present but "
                    "reported zero devices; coverage is unresolved."
                ],
            )
        ratio = numerator / eligible_i
        evidence_out["coverage_ratio"] = ratio
        evidence_out["eligible_devices"] = eligible_i
        if denominator_source:
            evidence_out["denominator_source"] = denominator_source
        conf = Confidence.MEDIUM if truncated else Confidence.HIGH
        limits = ["Intune device inventory pagination was truncated."] if truncated else []
        population = "eligible Entra device(s)" if matched is not None else "eligible device(s)"
        verb_ok = "are matched as managed" if matched is not None else "are managed"
        verb = "matched as managed" if matched is not None else "managed"
        if ratio >= 0.85 and not truncated:
            return Evaluation(
                status=FindingStatus.OK,
                summary=(
                    f"Intune enrollment coverage is high: {numerator} of {eligible_i} "
                    f"{population} {verb_ok} ({ratio * 100:.0f}%)."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "Most devices in the eligible population are enrolled in management."
                ),
                confidence=conf,
                data_sources=["graph.deviceManagement"],
                limitations=limits,
            )
        if ratio >= 0.5:
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    f"Partial Intune enrollment: {numerator} of {eligible_i} {population} "
                    f"{verb} ({ratio * 100:.0f}%)."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "Some devices in the eligible population are managed, but a "
                    "meaningful share may be missing."
                ),
                confidence=conf,
                data_sources=["graph.deviceManagement"],
                limitations=limits,
            )
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Large Intune enrollment gap: {numerator} of {eligible_i} {population} "
                f"{verb} ({ratio * 100:.0f}%)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "A large share of the eligible device population is not enrolled in management."
            ),
            confidence=conf,
            data_sources=["graph.deviceManagement"],
            limitations=limits,
        )

    if eligible is not None:
        return _coverage_verdict()

    if count == 0 and licensed:
        leverage_limits = [
            "Intune is licensed but no devices are enrolled in management.",
            "Licensed seats do not equal the device population; enrollment is "
            "reported as a licensing-leverage signal, not proven device coverage.",
        ]
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Intune is licensed but no managed devices were observed; enrollment "
                "coverage against an eligible device inventory could not be determined."
            ),
            evidence=evidence_out,
            customer_summary=(
                "No devices appear enrolled in management, so unmanaged devices can "
                "bypass cloud identity protections."
            ),
            confidence=Confidence.HIGH,
            data_sources=["graph.deviceManagement"],
            limitations=leverage_limits,
        )

    leverage_limits = ["Intune device inventory pagination was truncated."] if truncated else []
    leverage_limits.append(
        "Enrollment is compared against purchased license seats, not an "
        "authoritative device inventory; license counts do not necessarily equal "
        "the device population, so this is a licensing-leverage signal, not proven "
        "device coverage. Verify eligible devices in the Microsoft Intune admin center."
    )
    evidence_out["proxy"] = True
    evidence_sources = ["graph.deviceManagement", "graph.subscribedSkus (proxy licensing signal)"]
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            f"Observed {count} Intune-managed device(s)"
            + (f" vs ~{int(licensed)} purchased seats" if licensed else "")
            + ". Without an authoritative eligible device inventory this is a "
            "licensing-leverage signal, not confirmed enrollment coverage."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Without an authoritative eligible-device inventory we cannot confirm "
            "how much of the intended device population is actually managed."
        ),
        confidence=Confidence.LOW,
        data_sources=evidence_sources,
        limitations=leverage_limits,
    )

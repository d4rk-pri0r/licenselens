"""Intune enrollment coverage evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.endpoint_lib import (
    direct_meta,
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
    """Entitlement-to-enrollment: managed devices vs licensed Intune units."""
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
    truncated = bool((bundle or {}).get("truncated"))
    count = len(devices)
    evidence_out = {
        "managed_device_count": count,
        "licensed_units": licensed,
        "truncated": truncated,
    }

    if licensed is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Found {count} managed device(s), but could not determine licensed "
                "Intune unit count from SKUs."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some devices are enrolled, but we could not compare enrollment "
                "against purchased seats automatically."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement", "graph.subscribedSkus"],
        )
    licensed_i = int(licensed)
    if count == 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Intune is licensed but no devices are enrolled in management.",
            evidence=evidence_out,
            customer_summary=(
                "You appear to pay for device management, but no devices are enrolled. "
                "Unmanaged devices can bypass cloud identity protections."
            ),
            **direct_meta(),
        )
    ratio = count / licensed_i if licensed_i else 0.0
    evidence_out["coverage_ratio"] = ratio
    conf = Confidence.MEDIUM if truncated else Confidence.HIGH
    limits = ["Intune device inventory pagination was truncated."] if truncated else []
    if ratio >= 0.85 and not truncated:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Intune enrollment looks healthy: {count} managed vs ~{licensed_i} "
                f"licensed units ({ratio * 100:.0f}%)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Most paid device-management seats appear matched by enrolled devices."
            ),
            confidence=conf,
            data_sources=["graph.deviceManagement", "graph.subscribedSkus"],
            limitations=limits,
        )
    if ratio >= 0.5:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Partial Intune enrollment: {count} managed vs ~{licensed_i} licensed "
                f"units ({ratio * 100:.0f}%)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some devices are enrolled, but a noticeable share of seats still look unused."
            ),
            confidence=conf,
            data_sources=["graph.deviceManagement", "graph.subscribedSkus"],
            limitations=limits,
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"Large Intune enrollment gap: {count} managed vs ~{licensed_i} licensed "
            f"units ({ratio * 100:.0f}%)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "You appear to pay for device management on many seats, but few devices are enrolled."
        ),
        confidence=conf,
        data_sources=["graph.deviceManagement", "graph.subscribedSkus"],
        limitations=limits,
    )

"""MDE sensor-health and Defender XDR incident-readiness evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = [
    "evaluate_mde_sensor_health",
    "evaluate_xdr_incident_readiness",
]

_MDE_SOURCE = "mde.api.machines.health"
_XDR_SOURCE = "graph.security.incidents"


def evaluate_mde_sensor_health(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Inactive/unhealthy MDE sensor coverage."""
    del check
    summary = dict(evidence.get("mde_health") or {})
    sampled = _int(summary.get("machines_sampled"))
    if not sampled:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Defender for Endpoint sensor health inventory was empty.",
            evidence=summary,
            customer_summary="We could not read device sensor health for advanced PC protection.",
            confidence=Confidence.MEDIUM,
            data_sources=[_MDE_SOURCE],
            limitations=["MDE machine health inventory was empty; verify in the Defender portal."],
        )
    active = _int(summary.get("active_healthy"))
    impaired = _int(summary.get("impaired_communication"))
    no_data = _int(summary.get("no_sensor_data"))
    inactive = _int(summary.get("inactive"))
    unhealthy = max(sampled - active, impaired + no_data + inactive)
    truncated = bool(summary.get("truncated"))
    evidence_out = {
        **summary,
        "unhealthy_total": unhealthy,
        "healthy_ratio": active / sampled if sampled else 0.0,
    }
    conf = Confidence.MEDIUM if truncated else Confidence.HIGH
    limits = ["MDE health sample was truncated."] if truncated else []
    if unhealthy == 0:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"All {sampled} sampled Defender for Endpoint sensor(s) report active health.",
            evidence=evidence_out,
            customer_summary="Advanced device protection sensors look healthy.",
            confidence=conf,
            data_sources=[_MDE_SOURCE],
            limitations=limits,
        )
    ratio = unhealthy / sampled
    if ratio < 0.25:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{unhealthy} of {sampled} sampled Defender for Endpoint sensor(s) are "
                f"inactive or unhealthy."
            ),
            evidence=evidence_out,
            customer_summary=(
                "A few device-protection sensors look unhealthy and may be missing alerts."
            ),
            confidence=conf,
            data_sources=[_MDE_SOURCE],
            limitations=limits,
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"{unhealthy} of {sampled} sampled Defender for Endpoint sensor(s) are "
            f"inactive or unhealthy."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Many paid device-protection sensors are unhealthy, leaving devices partly blind."
        ),
        confidence=conf,
        data_sources=[_MDE_SOURCE],
        limitations=limits,
    )


def evaluate_xdr_incident_readiness(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Defender XDR correlation is proven by active incidents/alerts.

    Incident absence alone never becomes a gap or a pass: without active use we
    cannot prove correlation, so we fall back to manual verification.
    """
    del check
    bundle = dict(evidence.get("security_alerts_bundle") or {})
    incidents = int(bundle.get("incident_count") or 0)
    alerts = int(bundle.get("alert_count") or 0)
    evidence_out = {
        "incident_count": incidents,
        "alert_count": alerts,
        "capability_operating": bool(incidents or alerts),
    }
    if incidents or alerts:
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Defender XDR correlation is operating ({incidents} incident(s), "
                f"{alerts} alert(s) observed)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Cross-product incidents are being correlated, so XDR is actively in use."
            ),
            confidence=Confidence.HIGH,
            data_sources=[_XDR_SOURCE],
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            "No Defender XDR incidents or alerts observed; cannot confirm correlation "
            "is active from signal alone."
        ),
        evidence=evidence_out,
        customer_summary=(
            "We could not confirm cross-product incident correlation is active. "
            "Verify XDR is enabled in the Microsoft Defender portal."
        ),
        confidence=Confidence.MEDIUM,
        data_sources=[_XDR_SOURCE],
        limitations=["Absence of incidents is not treated as a failure; verify XDR in the portal."],
    )


def _int(value: Any) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0

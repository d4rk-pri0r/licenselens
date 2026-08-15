"""Intune endpoint-security baseline, policy coverage, and MDE connector evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.endpoint_lib import (
    atp_state,
    configuration_policies,
    direct_meta,
    intune_bundle,
    surface_error,
    unavailable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = [
    "evaluate_endpoint_mde_connector",
    "evaluate_endpoint_security_baseline",
    "evaluate_endpoint_security_policy_coverage",
]

_EXPECTED_FAMILIES: Final = {
    "antivirus": "antivirus",
    "firewall": "firewall",
    "disk_encryption": "disk encryption",
    "attack_surface_reduction": "attack surface reduction",
}


def evaluate_endpoint_security_baseline(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """An endpoint-security baseline profile is configured."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "configuration_policies")
    if error:
        return unavailable(
            "Intune endpoint-security policies could not be read; treated as unresolved.",
            surface="configuration_policies",
            customer_summary=(
                "We could not confirm whether an endpoint-security baseline is applied."
            ),
        )
    policies = configuration_policies(bundle)
    baselines = [p for p in policies if "baseline" in _family(p).lower()]
    evidence_out = {
        "configuration_policy_count": len(policies),
        "baseline_policy_count": len(baselines),
    }
    if not baselines:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No Intune endpoint-security baseline profile is configured.",
            evidence=evidence_out,
            customer_summary=(
                "No security baseline is applied, so device hardening settings are not enforced."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"{len(baselines)} endpoint-security baseline profile(s) configured.",
        evidence=evidence_out,
        customer_summary="A security baseline is applied to managed devices.",
        **direct_meta(),
    )


def evaluate_endpoint_security_policy_coverage(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Antivirus, firewall, disk-encryption, and ASR policy coverage."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "configuration_policies")
    if error:
        return unavailable(
            "Intune endpoint-security policies could not be read; treated as unresolved.",
            surface="configuration_policies",
            customer_summary="We could not confirm endpoint-security policy coverage.",
        )
    policies = configuration_policies(bundle)
    families = {_family(p).lower() for p in policies}
    present = [label for key, label in _EXPECTED_FAMILIES.items() if _family_hit(key, families)]
    evidence_out = {
        "expected_families": sorted(_EXPECTED_FAMILIES.values()),
        "covered_families": present,
        "coverage_ratio": len(present) / len(_EXPECTED_FAMILIES),
    }
    if not present:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="No antivirus, firewall, disk-encryption, or ASR policies are configured.",
            evidence=evidence_out,
            customer_summary="Core endpoint protections are not configured for managed devices.",
            **direct_meta(),
        )
    if len(present) < len(_EXPECTED_FAMILIES):
        missing = sorted(set(_EXPECTED_FAMILIES.values()) - set(present))
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Endpoint-security policy coverage is incomplete — missing: {', '.join(missing)}."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some core endpoint protections are configured, but others are missing."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=["graph.deviceManagement"],
            limitations=["Not every core endpoint-security family is covered."],
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Antivirus, firewall, disk-encryption, and ASR policies are all configured.",
        evidence=evidence_out,
        customer_summary="Core endpoint protections are configured for managed devices.",
        **direct_meta(),
    )


def evaluate_endpoint_mde_connector(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Intune-MDE connector is active (devices onboarded to Defender for Endpoint)."""
    del check
    bundle = intune_bundle(evidence)
    error = surface_error(bundle, "atp_onboarding_state")
    if error:
        return unavailable(
            "Intune-MDE connector status could not be read; treated as unresolved.",
            surface="atp_onboarding_state",
            customer_summary=(
                "We could not confirm whether Intune is connected to Defender for Endpoint."
            ),
        )
    atp = atp_state(bundle)
    if atp is None:
        return unavailable(
            "Intune-MDE connector onboarding summary was not returned.",
            surface="atp_onboarding_state",
            customer_summary="We could not confirm the Intune-MDE connector.",
        )
    onboarded = _int_field(atp, "onboardedDeviceCount")
    unknown = _int_field(atp, "unknownDeviceCount")
    unhealthy = _int_field(atp, "unhealthyDeviceCount")
    evidence_out = {
        "onboarded_device_count": onboarded,
        "unknown_device_count": unknown,
        "unhealthy_device_count": unhealthy,
    }
    if onboarded and onboarded > 0:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"Intune-MDE connector is active ({onboarded} device(s) onboarded).",
            evidence=evidence_out,
            customer_summary="Devices are flowing from Intune into Defender for Endpoint.",
            **direct_meta(),
        )
    if unknown and unknown > 0:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"No devices onboarded to Defender for Endpoint via Intune "
                f"({unknown} device(s) in unknown state)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "You appear to pay for device protection, but no devices are onboarded "
                "to Defender for Endpoint through Intune."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="No applicable devices to prove Intune-MDE connector state.",
        evidence=evidence_out,
        customer_summary=(
            "We could not confirm the Intune-MDE connector; there may be no applicable devices."
        ),
        confidence=Confidence.MEDIUM,
        data_sources=["graph.deviceManagement"],
        limitations=["No onboarded or unknown devices to confirm connector state."],
    )


def _family(policy: dict[str, Any]) -> str:
    ref = policy.get("templateReference") or {}
    if isinstance(ref, dict):
        return str(ref.get("templateFamily") or "")
    return ""


def _family_hit(key: str, families: set[str]) -> bool:
    return any(key.replace("_", "") in family.replace("_", "") for family in families)


def _int_field(mapping: dict[str, Any], name: str) -> int:
    value = mapping.get(name)
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0

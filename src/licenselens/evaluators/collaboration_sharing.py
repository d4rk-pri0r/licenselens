"""SharePoint / OneDrive sharing-scope and domain-restriction evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.collaboration_lib import (
    collaboration_bundle,
    direct_meta,
    items,
    not_applicable,
    prop_str,
    spo_sharing_capability,
    unavailable,
    usable,
)
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_SPO: Final = "spo_tenant"

# SharingCapability values that satisfy "Existing guests" or "Only people in your org".
_RESTRICTED_SHARING: Final = frozenset({"disabled", "existingexternalusersharingonly"})
# SharingCapability value that disables external sharing entirely.
_DISABLED_SHARING: Final = "disabled"

# Get-SPOTenant ConditionalAccessPolicy value that blocks unmanaged devices.
_BLOCK_ACCESS: Final = "blockaccess"


def _sharing_limited_result(
    *,
    capability: str | None,
    surface_name: str,
    label: str,
) -> Evaluation:
    if capability is None:
        return unavailable(
            f"{label} sharing capability could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name=surface_name,
            customer_summary=f"We could not confirm whether {label} sharing is locked down.",
        )
    evidence_out = {"sharing_capability": capability}
    if capability in _RESTRICTED_SHARING:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"{label} sharing is limited to existing guests or internal users.",
            evidence=evidence_out,
            customer_summary=f"{label} external sharing is restricted.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=f"{label} sharing allows broader external access than recommended.",
        evidence=evidence_out,
        customer_summary=(
            f"{label} sharing is more open than recommended. Restrict it to existing "
            "guests or internal users only."
        ),
        **direct_meta(),
    )


def evaluate_spo_sharing_capability_limited(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    return _sharing_limited_result(
        capability=spo_sharing_capability(bundle),
        surface_name="sharing_capability",
        label="SharePoint",
    )


def evaluate_spo_onedrive_sharing_limited(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    if not usable(bundle, _SPO, "onedrive_sharing"):
        return unavailable(
            "OneDrive sharing capability could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name="onedrive_sharing",
            customer_summary="We could not confirm whether OneDrive sharing is locked down.",
        )
    capability = None
    for item in items(bundle, _SPO, "onedrive_sharing"):
        value = prop_str(item, "OneDriveSharingCapability")
        if value:
            capability = value.strip().lower()
    if capability is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="OneDrive sharing setting was returned without a conclusive value.",
            evidence={"one_drive_sharing_capability": None},
            customer_summary="Confirm OneDrive sharing is restricted to existing guests.",
            confidence=Confidence.MEDIUM,
            limitations=["OneDriveSharingCapability was not reported."],
        )
    return _sharing_limited_result(
        capability=capability,
        surface_name="onedrive_sharing",
        label="OneDrive",
    )


def evaluate_spo_unmanaged_device_access(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    if not usable(bundle, _SPO, "unmanaged_device_policy"):
        return unavailable(
            "Unmanaged-device access policy could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name="unmanaged_device_policy",
            customer_summary="We could not confirm whether unmanaged devices are blocked.",
        )
    policy = None
    for item in items(bundle, _SPO, "unmanaged_device_policy"):
        value = prop_str(item, "ConditionalAccessPolicy")
        if value:
            policy = value.strip().lower()
    if policy is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Unmanaged-device policy was returned without a conclusive value.",
            evidence={"unmanaged_device_policy": None},
            customer_summary="Confirm unmanaged-device access is blocked in SharePoint.",
            confidence=Confidence.MEDIUM,
            limitations=["ConditionalAccessPolicy was not reported."],
        )
    evidence_out = {"unmanaged_device_policy": policy}
    if policy == _BLOCK_ACCESS:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Unmanaged devices are blocked from SharePoint and OneDrive content.",
            evidence=evidence_out,
            customer_summary="Unmanaged devices cannot reach SharePoint or OneDrive files.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            "Unmanaged-device access is not blocked "
            f"(policy: {policy or 'not set'})."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Devices your business does not manage can still open SharePoint and "
            "OneDrive content. Block unmanaged-device access."
        ),
        **direct_meta(),
    )


def _approved_partner_domains(evidence: dict[str, Any]) -> set[str]:
    raw = evidence.get("approved_partner_domains") or []
    if not isinstance(raw, list):
        return set()
    return {str(domain).strip().lower() for domain in raw if str(domain).strip()}


def _split_domains(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip().lower() for part in value.replace(",", " ").split() if part.strip()]


def evaluate_spo_domain_restrictions(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    sharing = spo_sharing_capability(bundle)
    if sharing == _DISABLED_SHARING:
        return not_applicable(
            "External sharing is disabled; domain restrictions are not applicable.",
            note="No external sharing is allowed, so domain restrictions are unnecessary.",
            evidence={"sharing_capability": sharing},
        )
    if sharing is None:
        return unavailable(
            "Sharing capability could not be read; domain restriction state is unresolved.",
            adapter=_SPO,
            surface_name="sharing_capability",
            customer_summary="We could not determine whether external sharing is domain-limited.",
        )
    if not usable(bundle, _SPO, "domain_restrictions"):
        return unavailable(
            "Domain restriction settings could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name="domain_restrictions",
            customer_summary="We could not confirm whether external sharing is domain-limited.",
        )
    mode = ""
    allowed: list[str] = []
    for item in items(bundle, _SPO, "domain_restrictions"):
        mode = prop_str(item, "SharingDomainRestrictionMode").strip().lower()
        allowed = _split_domains(prop_str(item, "SharingAllowedDomainList"))
    evidence_out = {
        "sharing_capability": sharing,
        "domain_restriction_mode": mode,
        "allowed_domains": allowed,
    }
    if mode != "allowlist":
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "External sharing is not limited to an approved domain allowlist "
                f"(mode: {mode or 'none'})."
            ),
            evidence=evidence_out,
            customer_summary=(
                "External sharing is not restricted to a list of approved partner domains."
            ),
            **direct_meta(),
        )
    approved = _approved_partner_domains(evidence)
    if approved:
        unapproved = [domain for domain in allowed if domain not in approved]
        evidence_out["unapproved_domains"] = unapproved
        if unapproved:
            return Evaluation(
                status=FindingStatus.GAP,
                summary=(
                    "Domain allowlist contains domains outside your approved "
                    f"partner list: {', '.join(sorted(unapproved))}."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "Your sharing allowlist includes domains not approved in this "
                    "report's configuration."
                ),
                **direct_meta(),
            )
    return Evaluation(
        status=FindingStatus.OK,
        summary="External sharing is limited to an approved domain allowlist.",
        evidence=evidence_out,
        customer_summary="External sharing is limited to approved partner domains.",
        **direct_meta(),
    )

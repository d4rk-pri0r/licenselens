"""Teams external-access, unmanaged-user, and email-integration evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.collectors.collaboration_models import CollaborationBundle, SurfaceStatus
from licenselens.evaluators.collaboration_lib import (
    collaboration_bundle,
    direct_meta,
    items,
    not_applicable,
    surface,
    unavailable,
    usable,
)
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_TEAMS_FED: Final = "teams_federation"
_TEAMS_CLIENT: Final = "teams_client"


def _domain_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(domain).strip().lower() for domain in value if str(domain).strip()]
    if isinstance(value, str):
        return [part.strip().lower() for part in value.replace(",", " ").split() if part.strip()]
    return []


def _approved_partner_domains(evidence: dict[str, Any]) -> set[str]:
    raw = evidence.get("approved_partner_domains") or []
    if not isinstance(raw, list):
        return set()
    return {str(domain).strip().lower() for domain in raw if str(domain).strip()}


def _surface_resolution(
    bundle: CollaborationBundle | None,
    adapter: str,
    name: str,
    *,
    label: str,
) -> Evaluation | None:
    """Return an Evaluation for unreadable/unsupported/denied surfaces, else None."""
    found = surface(bundle, adapter, name)
    if found is None:
        return unavailable(
            f"{label} could not be read; treated as unresolved.",
            adapter=adapter,
            surface_name=name,
            customer_summary=f"We could not confirm the {label} setting.",
        )
    if found.status is SurfaceStatus.UNSUPPORTED:
        return not_applicable(
            f"{label} is not supported on this cloud; no gap is inferred.",
            note=(
                "This setting is not available on the detected cloud. Verify manually if required."
            ),
            evidence={"adapter": adapter, "surface": name, "unsupported": True},
        )
    if found.status is not SurfaceStatus.OK:
        return unavailable(
            f"{label} could not be read (status: {found.status.value}); treated as unresolved.",
            adapter=adapter,
            surface_name=name,
            customer_summary=f"We could not confirm the {label} setting.",
        )
    return None


def evaluate_teams_external_access_per_domain(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    resolved = _surface_resolution(bundle, _TEAMS_FED, "federation", label="Teams external access")
    if resolved is not None:
        return resolved
    federated: bool | None = None
    allowed: list[str] = []
    for item in items(bundle, _TEAMS_FED, "federation"):
        raw = item.properties.get("AllowFederatedUsers")
        if isinstance(raw, bool):
            federated = raw
        allowed = _domain_list(item.properties.get("AllowedDomains"))
    evidence_out = {"allow_federated_users": federated, "allowed_domains": allowed}
    if federated is False:
        return Evaluation(
            status=FindingStatus.OK,
            summary="External access is disabled, so it is not open to all domains.",
            evidence=evidence_out,
            customer_summary="External access is turned off.",
            **direct_meta(),
        )
    open_federation = (not allowed) or any(domain == "*" for domain in allowed)
    if open_federation:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Teams external access is enabled for all domains.",
            evidence=evidence_out,
            customer_summary=(
                "External access is open to everyone. Allow only specific partner domains."
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
                    "Teams external access includes domains outside your approved "
                    f"partner list: {', '.join(sorted(unapproved))}."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "External access includes domains not approved in this report's configuration."
                ),
                **direct_meta(),
            )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Teams external access is limited to specific approved domains.",
        evidence=evidence_out,
        customer_summary="External access is limited to specific partner domains.",
        **direct_meta(),
    )


def _unmanaged_consumer_result(
    *,
    property_name: str,
    label: str,
    ok_summary: str,
    gap_summary: str,
    customer_ok: str,
    customer_gap: str,
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    resolved = _surface_resolution(
        bundle, _TEAMS_FED, "unmanaged_users", label=f"{label} unmanaged-user access"
    )
    if resolved is not None:
        return resolved
    enabled = False
    for item in items(bundle, _TEAMS_FED, "unmanaged_users"):
        raw = item.properties.get(property_name)
        if isinstance(raw, bool):
            enabled = raw
    evidence_out = {property_name: enabled}
    if enabled:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=gap_summary,
            evidence=evidence_out,
            customer_summary=customer_gap,
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=ok_summary,
        evidence=evidence_out,
        customer_summary=customer_ok,
        **direct_meta(),
    )


def evaluate_teams_unmanaged_inbound_blocked(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    return _unmanaged_consumer_result(
        property_name="EnableTeamsConsumerInbound",
        label="inbound",
        ok_summary="Unmanaged users cannot initiate contact with internal users.",
        gap_summary="Unmanaged users can initiate contact with internal users.",
        customer_ok="Unmanaged accounts cannot reach your team first.",
        customer_gap="Unmanaged accounts can contact your team. Block inbound unmanaged contact.",
        check=check,
        evidence=evidence,
    )


def evaluate_teams_unmanaged_outbound_blocked(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    return _unmanaged_consumer_result(
        property_name="EnableTeamsConsumerAccess",
        label="outbound",
        ok_summary="Internal users cannot initiate contact with unmanaged users.",
        gap_summary="Internal users can initiate contact with unmanaged users.",
        customer_ok="Your team cannot reach unmanaged accounts.",
        customer_gap=(
            "Your team can contact unmanaged accounts. Consider blocking outbound contact."
        ),
        check=check,
        evidence=evidence,
    )


def evaluate_teams_email_integration_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    resolved = _surface_resolution(
        bundle, _TEAMS_CLIENT, "email_integration", label="Teams email integration"
    )
    if resolved is not None:
        return resolved
    if not usable(bundle, _TEAMS_CLIENT, "email_integration"):
        return unavailable(
            "Teams email integration could not be read; treated as unresolved.",
            adapter=_TEAMS_CLIENT,
            surface_name="email_integration",
            customer_summary="We could not confirm whether channel email is disabled.",
        )
    allow_email = False
    for item in items(bundle, _TEAMS_CLIENT, "email_integration"):
        raw = item.properties.get("AllowEmailIntoChannel")
        if isinstance(raw, bool):
            allow_email = raw
    evidence_out = {"allow_email_into_channel": allow_email}
    if allow_email:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Teams channel email integration is enabled.",
            evidence=evidence_out,
            customer_summary=(
                "Channels can receive external email. Disable channel email unless required."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Teams channel email integration is disabled.",
        evidence=evidence_out,
        customer_summary="Channels cannot receive external email.",
        **direct_meta(),
    )


def evaluate_teams_guest_access_restricted(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    resolved = _surface_resolution(
        bundle, _TEAMS_CLIENT, "guest_access", label="Teams guest access"
    )
    if resolved is not None:
        return resolved
    allow_guest: bool | None = None
    allow_guest_calling: bool | None = None
    allow_guest_chat: bool | None = None
    for item in items(bundle, _TEAMS_CLIENT, "guest_access"):
        raw = item.properties.get("AllowGuestUser")
        if isinstance(raw, bool):
            allow_guest = raw
        raw_calling = item.properties.get("AllowGuestCalling")
        if isinstance(raw_calling, bool):
            allow_guest_calling = raw_calling
        raw_chat = item.properties.get("AllowGuestChat")
        if isinstance(raw_chat, bool):
            allow_guest_chat = raw_chat
    evidence_out = {
        "allow_guest_user": allow_guest,
        "allow_guest_calling": allow_guest_calling,
        "allow_guest_chat": allow_guest_chat,
    }
    if allow_guest is None:
        return unavailable(
            "Teams guest access setting could not be read; treated as unresolved.",
            adapter=_TEAMS_CLIENT,
            surface_name="guest_access",
            customer_summary="We could not confirm whether Teams guest access is restricted.",
        )
    if allow_guest is False:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Teams guest access is disabled tenant-wide.",
            evidence=evidence_out,
            customer_summary="External guests cannot be added to teams.",
            **direct_meta(),
        )
    restricted = allow_guest_calling is False and allow_guest_chat is False
    if restricted:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Teams guest access is enabled, but guest calling and chat are disabled. "
                "Domain-level guest restrictions could not be confirmed."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Guests can still be added to teams, though calling and chat are off. "
                "Confirm guest invitations are limited to approved domains."
            ),
            confidence=Confidence.MEDIUM,
            limitations=[
                "Guest domain allow-listing is managed in Microsoft Entra, not Teams "
                "PowerShell; verify the allowlist there."
            ],
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Teams guest access is wide open.",
        evidence=evidence_out,
        customer_summary=(
            "Anyone can be invited as a guest with calling and chat. Restrict guest "
            "access or limit it to approved domains."
        ),
        **direct_meta(),
    )

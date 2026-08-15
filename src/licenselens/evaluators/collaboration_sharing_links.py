"""SharePoint default-link, anyone-link, and verification-code evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.collaboration_lib import (
    collaboration_bundle,
    direct_meta,
    items,
    not_applicable,
    prop_int,
    prop_str,
    spo_sharing_capability,
    unavailable,
    usable,
)
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus

_SPO: Final = "spo_tenant"
_ANYONE_SHARING: Final = "externaluserandguestsharing"
_DISABLED_SHARING: Final = "disabled"
_ANYONE_MAX_DAYS: Final = 30


def _anyone_links_enabled(bundle: Any) -> bool:
    return spo_sharing_capability(bundle) == _ANYONE_SHARING


def evaluate_spo_default_link_specific(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    if not usable(bundle, _SPO, "default_link"):
        return unavailable(
            "Default sharing link type could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name="default_link",
            customer_summary="We could not confirm the default sharing link scope.",
        )
    link_type = ""
    for item in items(bundle, _SPO, "default_link"):
        link_type = prop_str(item, "DefaultSharingLinkType").strip().lower()
    evidence_out = {"default_link_type": link_type}
    if link_type == "direct":
        return Evaluation(
            status=FindingStatus.OK,
            summary="Default sharing links are scoped to specific people.",
            evidence=evidence_out,
            customer_summary="New sharing links only reach the specific people you choose.",
            **direct_meta(),
        )
    if link_type == "internal":
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Default sharing links are internal, not specific-people scoped.",
            evidence=evidence_out,
            customer_summary=(
                "New links default to everyone in your organization. Prefer specific-people links."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Default sharing links are not scoped to specific people.",
        evidence=evidence_out,
        customer_summary=(
            "New sharing links may be broader than intended. Scope them to specific people."
        ),
        **direct_meta(),
    )


def evaluate_spo_default_link_view(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    if not usable(bundle, _SPO, "default_link"):
        return unavailable(
            "Default sharing link permission could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name="default_link",
            customer_summary="We could not confirm the default sharing link permission.",
        )
    permission = ""
    for item in items(bundle, _SPO, "default_link"):
        permission = prop_str(item, "DefaultLinkPermission").strip().lower()
    evidence_out = {"default_link_permission": permission}
    if permission == "view":
        return Evaluation(
            status=FindingStatus.OK,
            summary="Default sharing links grant view-only permission.",
            evidence=evidence_out,
            customer_summary="New sharing links are view-only by default.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Default sharing links grant more than view-only permission.",
        evidence=evidence_out,
        customer_summary="New sharing links may allow editing. Set the default to view-only.",
        **direct_meta(),
    )


def evaluate_spo_anyone_link_expiration(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    sharing = spo_sharing_capability(bundle)
    if sharing is not None and not _anyone_links_enabled(bundle):
        return not_applicable(
            "Anyone links are not enabled; expiration policy is not applicable.",
            note="Anyone links are disabled, so link expiration is not required.",
            evidence={"sharing_capability": sharing},
        )
    if not usable(bundle, _SPO, "anyone_link_expiration"):
        return unavailable(
            "Anyone-link expiration could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name="anyone_link_expiration",
            customer_summary="We could not confirm whether anyone links expire.",
        )
    days = None
    for item in items(bundle, _SPO, "anyone_link_expiration"):
        days = prop_int(item, "RequireAnonymousLinksExpireInDays")
    evidence_out = {"anyone_link_expire_days": days, "sharing_capability": sharing}
    if days is not None and 1 <= days <= _ANYONE_MAX_DAYS:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"Anyone links expire within {days} days.",
            evidence=evidence_out,
            customer_summary="Anyone links expire automatically within a safe window.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Anyone links do not expire within the recommended window.",
        evidence=evidence_out,
        customer_summary="Anyone links may never expire. Set them to expire within 30 days.",
        **direct_meta(),
    )


def evaluate_spo_anyone_link_view(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    sharing = spo_sharing_capability(bundle)
    if sharing is not None and not _anyone_links_enabled(bundle):
        return not_applicable(
            "Anyone links are not enabled; link permission policy is not applicable.",
            note="Anyone links are disabled, so link permissions are not required.",
            evidence={"sharing_capability": sharing},
        )
    if not usable(bundle, _SPO, "anyone_link_permissions"):
        return unavailable(
            "Anyone-link permissions could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name="anyone_link_permissions",
            customer_summary="We could not confirm whether anyone links are view-only.",
        )
    file_type = ""
    folder_type = ""
    for item in items(bundle, _SPO, "anyone_link_permissions"):
        file_type = prop_str(item, "FileAnonymousLinkType").strip().lower()
        folder_type = prop_str(item, "FolderAnonymousLinkType").strip().lower()
    evidence_out = {
        "file_anonymous_link_type": file_type,
        "folder_anonymous_link_type": folder_type,
        "sharing_capability": sharing,
    }
    if file_type == "view" and folder_type == "view":
        return Evaluation(
            status=FindingStatus.OK,
            summary="Anyone links are limited to view-only permission.",
            evidence=evidence_out,
            customer_summary="Anyone links are view-only.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Anyone links allow more than view-only permission.",
        evidence=evidence_out,
        customer_summary="Anyone links may allow editing. Limit them to view-only.",
        **direct_meta(),
    )


def evaluate_spo_verification_reauth(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    sharing = spo_sharing_capability(bundle)
    if sharing == _DISABLED_SHARING:
        return not_applicable(
            "External sharing is disabled; verification-code reauth is not applicable.",
            note="No external sharing is allowed, so reauthentication is not required.",
            evidence={"sharing_capability": sharing},
        )
    if not usable(bundle, _SPO, "reauth_days"):
        return unavailable(
            "Verification-code reauthentication could not be read; treated as unresolved.",
            adapter=_SPO,
            surface_name="reauth_days",
            customer_summary="We could not confirm verification-code reauthentication.",
        )
    required = False
    days = None
    for item in items(bundle, _SPO, "reauth_days"):
        required = item.properties.get("EmailAttestationRequired") is True
        days = prop_int(item, "EmailAttestationReAuthDays")
    evidence_out = {
        "email_attestation_required": required,
        "email_attestation_reauth_days": days,
        "sharing_capability": sharing,
    }
    if required and days is not None and 1 <= days <= _ANYONE_MAX_DAYS:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"Verification-code users must reauthenticate within {days} days.",
            evidence=evidence_out,
            customer_summary="Verification-code access reauthenticates within a safe window.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Verification-code reauthentication is not set to 30 days or less.",
        evidence=evidence_out,
        customer_summary=(
            "Verification-code access may be indefinite. Require reauthentication within 30 days."
        ),
        **direct_meta(),
    )

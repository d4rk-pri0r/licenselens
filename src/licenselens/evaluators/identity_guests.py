"""Guest and cross-tenant access evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

# Guest user role template IDs.
_GUEST_USER: Final = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
_GUEST_LIMITED: Final = "2af84b1e-32c8-42b7-82bc-daa82404023b"
_USER_DEFAULT: Final = "a0b1b346-4d3e-4e8b-98f8-753987be4970"


def _authz(evidence: dict[str, Any]) -> dict[str, Any]:
    policy = evidence.get("authorization_policy") or {}
    return policy if isinstance(policy, dict) else {}


def _cross_default(evidence: dict[str, Any]) -> dict[str, Any]:
    bundle = evidence.get("guests_bundle") or {}
    if isinstance(bundle, dict) and isinstance(bundle.get("default"), dict):
        return bundle["default"]
    value = evidence.get("cross_tenant_access_default") or {}
    return value if isinstance(value, dict) else {}


def evaluate_guest_directory_access_limited(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policy = _authz(evidence)
    role_id = str(policy.get("guestUserRoleId") or "").lower()
    evidence_out = {"guest_user_role_id": role_id or None}
    if role_id in {_GUEST_USER, _GUEST_LIMITED}:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Guest users have limited or restricted directory permissions.",
            evidence=evidence_out,
            customer_summary="Guests cannot freely browse your full directory like employees.",
        )
    if role_id == _USER_DEFAULT:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Guest users have the same directory permissions as members.",
            evidence=evidence_out,
            customer_summary=(
                "Guest accounts can see directory information similar to full members."
            ),
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="Guest directory role setting could not be classified.",
        evidence=evidence_out,
        customer_summary="We could not confirm how much directory access guests have.",
    )


def evaluate_guest_inviter_restricted(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policy = _authz(evidence)
    allow = str(policy.get("allowInvitesFrom") or "").lower()
    evidence_out = {"allow_invites_from": allow or None}
    if allow in {"adminsandguestinviters", "none", "admins"}:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Guest invitations are limited to admins and/or Guest Inviter role.",
            evidence=evidence_out,
            customer_summary="Not everyone can invite external guests into your tenant.",
        )
    if allow in {"everyone", "adminsguestinvitersandallmembers", ""}:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Guest invitations are broadly allowed (allowInvitesFrom={allow or 'default'})."
            ),
            evidence=evidence_out,
            customer_summary="Many users can invite external guests without a special role.",
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=f"Guest invitation setting is uncommon ({allow}).",
        evidence=evidence_out,
        customer_summary="Guest invitation controls need a manual review.",
    )


def evaluate_guest_invite_domains(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    allowed = list(evidence.get("approved_guest_domains") or [])
    default = _cross_default(evidence)
    evidence_out = {
        "approved_guest_domains": allowed,
        "cross_tenant_default_present": bool(default),
        "manual": True,
    }
    if not allowed:
        return Evaluation(
            status=FindingStatus.SKIPPED,
            summary=(
                "Guest invite domain allowlisting requires approved partner "
                "domains in your configured settings."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We cannot judge guest invite domains until your organization lists "
                "approved partner domains in your configured settings."
            ),
            confidence=Confidence.LOW,
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=(
            "Approved guest domains are configured in your settings; confirm the "
            "Entra B2B collaboration allowlist matches them."
        ),
        evidence=evidence_out,
        customer_summary=(
            "Partner domains are listed in your configured settings — verify the "
            "live Entra allowlist matches that list."
        ),
    )


def evaluate_cross_tenant_defaults(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    default = _cross_default(evidence)
    inbound = default.get("b2bCollaborationInbound") or {}
    users = (inbound or {}).get("usersAndGroups") or {}
    access = str(users.get("accessType") or "").lower()
    evidence_out = {"inbound_access_type": access or None}
    if access in {"blocked", "allowed"} and access == "blocked":
        return Evaluation(
            status=FindingStatus.OK,
            summary="Default cross-tenant B2B inbound collaboration is blocked.",
            evidence=evidence_out,
            customer_summary="Unknown external tenants cannot collaborate in by default.",
        )
    if access == "allowed":
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Default cross-tenant B2B inbound collaboration is allowed.",
            evidence=evidence_out,
            customer_summary=(
                "External tenants can collaborate by default — tighten this unless "
                "partner allowlists are intentional."
            ),
        )
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary="Cross-tenant default collaboration setting was not conclusive.",
        evidence=evidence_out,
        customer_summary="Review cross-tenant access defaults in Entra External Identities.",
    )


def _mfa_trust(value: Any) -> bool | None:
    if not isinstance(value, dict):
        return None
    accepted = value.get("isMfaAccepted")
    if accepted is None:
        return None
    return bool(accepted)


def evaluate_cross_tenant_mfa_trust(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Cross-tenant inbound MFA claims are not trusted by default."""
    del check

    if evidence.get("guests_bundle_error"):
        return Evaluation(
            status=FindingStatus.ERROR,
            summary="Cross-tenant access settings could not be read: "
            + str(evidence["guests_bundle_error"]),
            evidence={"error": str(evidence["guests_bundle_error"])},
        )

    bundle = evidence.get("guests_bundle") or {}
    if not isinstance(bundle, dict):
        bundle = {}
    default = bundle.get("default")
    if not isinstance(default, dict):
        default = _cross_default(evidence)
    partners = list(bundle.get("partners") or [])

    inbound_trust = (default.get("b2bCollaborationInbound") or {}).get(
        "trustSettings"
    ) or {}
    outbound_trust = (default.get("b2bCollaborationOutbound") or {}).get(
        "trustSettings"
    ) or {}
    inbound_default = _mfa_trust(inbound_trust.get("inboundTrust"))
    outbound_default = _mfa_trust(outbound_trust.get("outboundTrust"))

    partner_inbound_trust = 0
    partner_outbound_trust = 0
    for partner in partners:
        if not isinstance(partner, dict):
            continue
        pinbound = _mfa_trust(partner.get("inboundTrust")) or _mfa_trust(
            ((partner.get("b2bCollaborationInbound") or {}).get("trustSettings") or {}).get(
                "inboundTrust"
            )
        )
        poutbound = _mfa_trust(partner.get("outboundTrust")) or _mfa_trust(
            ((partner.get("b2bCollaborationOutbound") or {}).get("trustSettings") or {}).get(
                "outboundTrust"
            )
        )
        if pinbound is True:
            partner_inbound_trust += 1
        if poutbound is True:
            partner_outbound_trust += 1

    evidence_out = {
        "inbound_mfa_trust_default": inbound_default,
        "outbound_mfa_trust_default": outbound_default,
        "partner_count": len(partners),
        "partner_inbound_mfa_trust_count": partner_inbound_trust,
        "partner_outbound_mfa_trust_count": partner_outbound_trust,
    }

    if inbound_default is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Cross-tenant inbound MFA trust setting was not conclusive; "
                "verify it in Entra External Identities."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not confirm whether your tenant accepts other "
                "tenants' multi-factor authentication claims by default."
            ),
        )

    if inbound_default is True:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "Cross-tenant inbound settings accept multi-factor "
                "authentication claims from external tenants by default."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Guests from other tenants can satisfy your multi-factor "
                "requirements with their home tenant's MFA — which you cannot "
                "verify — instead of completing your own."
            ),
        )

    partner_suffix = (
        f"; {partner_inbound_trust} partner(s) are explicitly trusted."
        if partner_inbound_trust
        else "."
    )
    return Evaluation(
        status=FindingStatus.OK,
        summary=(
            "Cross-tenant inbound settings do not accept external MFA claims "
            "by default" + partner_suffix
        ),
        evidence=evidence_out,
        customer_summary=(
            "External tenants' multi-factor authentication claims are not "
            "trusted by default, so guests must meet your own sign-in "
            "requirements unless a specific partner is explicitly trusted."
        ),
    )

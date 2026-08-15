"""Exchange Online mail-flow evaluators (forwarding, SMTP AUTH, sharing, warnings, audit)."""

from __future__ import annotations

from typing import Any, Final

from licenselens.collectors.exchange_models import PolicyItem
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    any_enabled_with,
    direct_meta,
    exchange_bundle,
    items,
    prop,
    prop_bool,
    surface,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_ANON_PREFIX: Final = "anonymous"
_PARTIAL_META: Final = {
    "confidence": Confidence.MEDIUM,
    "limitations": ["Surface was not readable via Exchange Online PowerShell; verify in portal."],
}


def _unavailable(
    summary: str,
    *,
    adapter: str,
    name: str,
    customer_summary: str,
) -> Evaluation:
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=summary,
        evidence={"surface": name, "adapter": adapter, "readable": False},
        customer_summary=customer_summary,
        **_PARTIAL_META,
    )


def evaluate_exo_forwarding_external_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    surface_obj = surface(bundle, "exo_remote_domains", "remote_domains")
    allowed = {str(d).lower() for d in (evidence.get("allowed_forwarding_domains") or [])}
    if surface_obj is None or not usable(bundle, "exo_remote_domains", "remote_domains"):
        return _unavailable(
            "Automatic forwarding could not be read; treated as unresolved.",
            adapter="exo_remote_domains",
            name="remote_domains",
            customer_summary=(
                "We could not confirm whether mail forwarding to external addresses is locked down."
            ),
        )

    forwarding: list[PolicyItem] = [
        item
        for item in items(bundle, "exo_remote_domains", "remote_domains")
        if prop_bool(item, "AutoForwardEnabled")
    ]
    domain_names = {str(prop(item, "DomainName") or "").lower() for item in forwarding}
    unapproved = [name for name in domain_names if name and name not in allowed]
    evidence_out = {
        "forwarding_domains": sorted(domain_names),
        "allowed_forwarding_domains": sorted(allowed),
        "unapproved_forwarding": sorted(unapproved),
    }
    if unapproved:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Automatic forwarding to external domains is enabled for "
                f"{', '.join(sorted(unapproved))} without a profile allowlist entry."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Email forwarding to outside addresses is on. Only keep it for "
                "domains you have explicitly approved."
            ),
            **direct_meta(),
        )
    if forwarding:
        return Evaluation(
            status=FindingStatus.OK,
            summary=("Automatic forwarding is limited to profile-approved external domains only."),
            evidence=evidence_out,
            customer_summary="External mail forwarding matches your approved allowlist.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Automatic forwarding to external domains is disabled.",
        evidence=evidence_out,
        customer_summary="External mail forwarding is locked down.",
        **direct_meta(),
    )


def evaluate_exo_smtp_auth_disabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, "exo_smtp_auth", "smtp_auth"):
        return _unavailable(
            "SMTP AUTH posture could not be read; treated as unresolved.",
            adapter="exo_smtp_auth",
            name="smtp_auth",
            customer_summary="We could not confirm whether SMTP AUTH is turned off.",
        )
    smtp_items = items(bundle, "exo_smtp_auth", "smtp_auth")
    disabled = prop_bool(smtp_items[0], "SmtpClientAuthenticationDisabled") if smtp_items else None
    value = prop(smtp_items[0], "SmtpClientAuthenticationDisabled") if smtp_items else None
    evidence_out = {"smtp_client_authentication_disabled": value}
    if isinstance(value, bool) is False:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="SMTP AUTH setting was returned without a conclusive value.",
            evidence=evidence_out,
            customer_summary="Confirm SMTP AUTH is disabled for the organization.",
            confidence=Confidence.MEDIUM,
            limitations=["SmtpClientAuthenticationDisabled was not reported as a boolean."],
        )
    if disabled:
        return Evaluation(
            status=FindingStatus.OK,
            summary="SMTP AUTH is disabled at the organization level.",
            evidence=evidence_out,
            customer_summary="Legacy basic-auth email submission is turned off.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="SMTP AUTH is enabled at the organization level.",
        evidence=evidence_out,
        customer_summary=(
            "Basic-auth email submission is still on, which can bypass modern sign-in. "
            "Turn it off unless a legacy app truly needs it."
        ),
        **direct_meta(),
    )


def _anonymous_sharing(bundle: Any) -> bool | None:
    if not usable(bundle, "exo_sharing", "sharing_policies"):
        return None
    for item in items(bundle, "exo_sharing", "sharing_policies"):
        domains = prop(item, "Domains")
        if isinstance(domains, list) and any(
            str(entry).lower().startswith(_ANON_PREFIX) for entry in domains
        ):
            return True
    return False


def _sharing_result(
    *,
    kind: str,
    anonymous: bool | None,
) -> Evaluation:
    label = f"{kind} sharing"
    evidence_out = {"shares_with_all_domains": anonymous, "kind": kind}
    if anonymous is None:
        return _unavailable(
            f"{label} could not be read; treated as unresolved.",
            adapter="exo_sharing",
            name="sharing_policies",
            customer_summary=f"We could not confirm whether {label} is limited.",
        )
    if anonymous:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"{label} is enabled with all domains.",
            evidence=evidence_out,
            customer_summary=(
                f"Your {kind} sharing is open to everyone by default. "
                "Limit it to specific partner domains."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"{label} is not shared with all domains.",
        evidence=evidence_out,
        customer_summary=f"{kind} sharing is limited to approved domains.",
        **direct_meta(),
    )


def evaluate_exo_sharing_contact_not_all_domains(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return _sharing_result(
        kind="Contact folder", anonymous=_anonymous_sharing(exchange_bundle(evidence))
    )


def evaluate_exo_sharing_calendar_not_all_domains(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    result = _sharing_result(
        kind="Calendar", anonymous=_anonymous_sharing(exchange_bundle(evidence))
    )
    result.limitations = [
        *result.limitations,
        "Calendar free/busy vs full-detail sharing granularity is not distinguished.",
    ]
    return result


def _external_rule_warning(bundle: Any) -> bool | None:
    if not usable(bundle, "exo_transport", "transport_rules"):
        return None
    for item in items(bundle, "exo_transport", "transport_rules"):
        scope = str(prop(item, "FromScope") or "").lower()
        if "notinorganization" not in scope and "external" not in scope:
            continue
        if prop(item, "PrependSubject") or prop(item, "ApplyHtmlDisclaimerText"):
            return True
    return False


def evaluate_exo_external_sender_warnings(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    mailtips = any_enabled_with(
        bundle,
        "exo_transport",
        "external_warning",
        lambda item: prop_bool(item, "MailTipsExternalRecipientsTipsEnabled"),
    )
    rule = _external_rule_warning(bundle)
    evidence_out = {
        "mail_tips_external_tips": mailtips,
        "external_sender_rule": rule,
    }
    if mailtips or rule:
        return Evaluation(
            status=FindingStatus.OK,
            summary="External sender warnings are enabled (mail tips and/or transport rule).",
            evidence=evidence_out,
            customer_summary=(
                "Users see a clear flag when mail comes from outside your organization."
            ),
            **direct_meta(),
        )
    if mailtips is None and rule is None:
        return _unavailable(
            "External sender warning signals could not be read.",
            adapter="exo_transport",
            name="external_warning",
            customer_summary="We could not confirm whether external mail is flagged for users.",
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="External sender warnings are not configured.",
        evidence=evidence_out,
        customer_summary=(
            "Users get no obvious cue when email comes from outside. "
            "Turn on external sender mail tips or an [External] subject rule."
        ),
        **direct_meta(),
    )


def evaluate_exo_mailbox_audit_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, "exo_audit", "organization_audit"):
        return _unavailable(
            "Mailbox audit state could not be read; treated as unresolved.",
            adapter="exo_audit",
            name="organization_audit",
            customer_summary="We could not confirm whether mailbox auditing is on.",
        )
    audit_items = items(bundle, "exo_audit", "organization_audit")
    disabled = prop_bool(audit_items[0], "AuditDisabled") if audit_items else None
    value = prop(audit_items[0], "AuditDisabled") if audit_items else None
    evidence_out = {"audit_disabled": value}
    if isinstance(value, bool) is False:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Mailbox audit setting was returned without a conclusive value.",
            evidence=evidence_out,
            customer_summary="Confirm mailbox auditing is enabled.",
            confidence=Confidence.MEDIUM,
            limitations=["AuditDisabled was not reported as a boolean."],
        )
    if not disabled:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Mailbox auditing is enabled for the organization.",
            evidence=evidence_out,
            customer_summary="Mailbox access is being recorded for later investigation.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Mailbox auditing is disabled for the organization.",
        evidence=evidence_out,
        customer_summary="Mailbox activity is not being logged. Turn auditing back on.",
        **direct_meta(),
    )

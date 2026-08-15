"""Exchange sharing, external-sender warning, and mailbox-audit evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    any_enabled_with,
    direct_meta,
    exchange_bundle,
    items,
    prop,
    prop_bool,
    usable,
)
from licenselens.evaluators.exchange_mailflow_core import unavailable
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_ANON_PREFIX: Final = "anonymous"


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
        return unavailable(
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
        return unavailable(
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
        return unavailable(
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

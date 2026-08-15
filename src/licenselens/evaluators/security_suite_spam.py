"""Anti-spam, connection-filter, and Safe Attachments for SPO/Teams evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    direct_meta,
    enabled_items,
    exchange_bundle,
    prop,
    prop_bool,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_THREAT = "exo_threat_policies"
_JUNK_OR_BLOCK: Final = frozenset(
    {"movetojmf", "quarantine", "delete", "redirect", "redirectmessage"}
)
_SPAM_ACTION_FIELDS: Final = (
    "SpamAction",
    "HighConfidenceSpamAction",
    "PhishSpamAction",
    "HighConfidencePhishAction",
)


def _unread(surface: str, summary: str, customer: str) -> Evaluation:
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=summary,
        evidence={"surface": surface, "readable": False},
        customer_summary=customer,
        confidence=Confidence.MEDIUM,
        limitations=[f"{surface} surface was not readable via PowerShell."],
    )


def _list_props(bundle: Any, surface: str, fields: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for item in enabled_items(bundle, _THREAT, surface):
        for field in fields:
            value = prop(item, field)
            if isinstance(value, list):
                values.extend(f"{item.name}:{entry}" for entry in value if entry)
            elif value:
                values.append(f"{item.name}:{value}")
    return values


def _action_delivers_to_inbox(action: object) -> bool:
    text = str(action or "").strip().lower().replace(" ", "")
    if not text:
        return True
    return text not in _JUNK_OR_BLOCK


def evaluate_mdo_spam_phish_not_inbox(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _THREAT, "anti_spam"):
        return _unread(
            "anti_spam",
            "Anti-spam policies could not be read; treated as unresolved.",
            "We could not confirm whether spam and phishing stay out of inboxes.",
        )
    weak = [
        f"{item.name}:{field}={prop(item, field)}"
        for item in enabled_items(bundle, _THREAT, "anti_spam")
        for field in _SPAM_ACTION_FIELDS
        if _action_delivers_to_inbox(prop(item, field))
    ]
    evidence_out = {
        "weak_actions": weak,
        "policies": len(enabled_items(bundle, _THREAT, "anti_spam")),
    }
    if weak:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Spam or phishing actions still allow delivery to the inbox.",
            evidence=evidence_out,
            customer_summary=(
                "Some spam or phishing mail can still land in inboxes. "
                "Quarantine or junk those messages instead."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Spam and phishing actions keep messages out of the inbox.",
        evidence=evidence_out,
        customer_summary="Spam and phishing are kept out of user inboxes.",
        **direct_meta(),
    )


def evaluate_mdo_anti_spam_no_allowed_domains(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _THREAT, "anti_spam"):
        return _unread(
            "anti_spam",
            "Anti-spam allow lists could not be read; treated as unresolved.",
            "We could not confirm whether anti-spam allow lists are empty.",
        )
    allowed = _list_props(bundle, "anti_spam", ("AllowedSenderDomains", "AllowedSenders"))
    evidence_out = {"allowed_entries": sorted(allowed)}
    if allowed:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Anti-spam policies include allowed senders or domains.",
            evidence=evidence_out,
            customer_summary=(
                "Allow-listed senders bypass spam filters. Remove broad allow lists."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Anti-spam policies do not include allowed senders or domains.",
        evidence=evidence_out,
        customer_summary="No broad anti-spam allow lists are configured.",
        **direct_meta(),
    )


def evaluate_mdo_connection_filter_no_ip_allow(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _THREAT, "connection_filter"):
        return _unread(
            "connection_filter",
            "Connection filter IP allow list could not be read.",
            "We could not confirm whether IP allow lists bypass filtering.",
        )
    allow_ips = _list_props(bundle, "connection_filter", ("IPAllowList",))
    # strip policy name prefix for cleaner evidence
    cleaned = [entry.split(":", 1)[-1] for entry in allow_ips]
    evidence_out = {"ip_allow_list": sorted(cleaned)}
    if cleaned:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Connection filter IP allow list is not empty.",
            evidence=evidence_out,
            customer_summary=(
                "IP allow lists let mail skip important filters. Clear the allow list."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Connection filter IP allow list is empty.",
        evidence=evidence_out,
        customer_summary="No IP allow list bypasses email filtering.",
        **direct_meta(),
    )


def evaluate_mdo_connection_filter_no_safe_list(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _THREAT, "connection_filter"):
        return _unread(
            "connection_filter",
            "Connection filter safe list setting could not be read.",
            "We could not confirm whether the safe list is disabled.",
        )
    enabled = any(
        prop_bool(item, "EnableSafeList")
        for item in enabled_items(bundle, _THREAT, "connection_filter")
    )
    evidence_out = {"enable_safe_list": enabled}
    if enabled:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Connection filter safe list is enabled.",
            evidence=evidence_out,
            customer_summary="The safe list lets some senders skip filtering. Turn it off.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Connection filter safe list is disabled.",
        evidence=evidence_out,
        customer_summary="Safe-list bypass is turned off.",
        **direct_meta(),
    )


def evaluate_mdo_safe_attachments_spo_teams(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _THREAT, "atp_global"):
        return _unread(
            "atp_global",
            "Safe Attachments for SharePoint/OneDrive/Teams could not be read.",
            "We could not confirm malware scanning for SharePoint, OneDrive, and Teams.",
        )
    enabled = any(
        prop_bool(item, "EnableATPForSPOTeamsODB")
        or prop_bool(item, "EnableSafeAttachmentsForSPOTeamsODB")
        for item in enabled_items(bundle, _THREAT, "atp_global")
    )
    evidence_out = {"enable_atp_for_spo_teams_odb": enabled}
    if enabled:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Safe Attachments covers SharePoint, OneDrive, and Teams.",
            evidence=evidence_out,
            customer_summary="Files in SharePoint, OneDrive, and Teams are scanned for malware.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Safe Attachments is not enabled for SharePoint, OneDrive, and Teams.",
        evidence=evidence_out,
        customer_summary=(
            "Files shared in SharePoint, OneDrive, or Teams are not scanned. "
            "Turn on Defender for Office 365 for those apps."
        ),
        **direct_meta(),
    )


def _manual(summary: str, customer: str, limitation: str) -> Evaluation:
    return Evaluation(
        status=FindingStatus.SKIPPED,
        summary=summary,
        evidence={"manual": True, "evaluation_mode": "manual"},
        customer_summary=customer,
        confidence=Confidence.LOW,
        limitations=[limitation],
    )


def evaluate_mdo_alert_policies_manual(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check, evidence
    return _manual(
        "Defender alert policies are portal-configured and not fully automated here.",
        "Confirm required suspicious-email and connector alerts are enabled.",
        "Manual verification required in Microsoft 365 Defender alert policies.",
    )


def evaluate_mdo_audit_retention_manual(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check, evidence
    return _manual(
        "Unified audit retention depends on license tier and is not fully automated.",
        "Confirm audit logs stay searchable 3 months and retrievable 12 months.",
        "Manual verification required for audit log retention.",
    )

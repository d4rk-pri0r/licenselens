"""Defender for Office threat-policy evaluators (malware, Safe Links/Attachments, impersonation)."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    any_enabled_with,
    direct_meta,
    exchange_bundle,
    prop,
    prop_bool,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_THREAT = "exo_threat_policies"
_BLOCK_ACTIONS: Final = frozenset({"block", "dynamicdelivery", "replace", "remove"})


def _flag(bundle: Any, surface_name: str, prop_name: str) -> bool | None:
    return any_enabled_with(bundle, _THREAT, surface_name, lambda item: prop_bool(item, prop_name))


def _bool_flag_result(
    *,
    surface_name: str,
    prop_name: str,
    flag: bool | None,
    ok_summary: str,
    ok_customer: str,
    gap_summary: str,
    gap_customer: str,
    note: str = "",
) -> Evaluation:
    evidence_out = {"surface": surface_name, "property": prop_name, "value": flag}
    if note:
        evidence_out["note"] = note
    if flag is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"Threat policy surface '{surface_name}' could not be read.",
            evidence=evidence_out,
            customer_summary="We could not confirm this email protection from a direct read.",
            confidence=Confidence.MEDIUM,
            limitations=["Threat policy surface was not readable via PowerShell."],
        )
    if flag:
        return Evaluation(
            status=FindingStatus.OK,
            summary=ok_summary,
            evidence=evidence_out,
            customer_summary=ok_customer,
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=gap_summary,
        evidence=evidence_out,
        customer_summary=gap_customer,
        **direct_meta(),
    )


def evaluate_mdo_malware_file_filter(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    return _bool_flag_result(
        surface_name="anti_malware",
        prop_name="EnableFileFilter",
        flag=_flag(bundle, "anti_malware", "EnableFileFilter"),
        ok_summary="Click-to-run attachment filtering (common attachments filter) is enabled.",
        ok_customer="Risky file types like .exe are filtered from email.",
        gap_summary="Common-attachment file filtering is not enabled.",
        gap_customer=(
            "Click-to-run attachments such as .exe or .cmd are not filtered. "
            "Enable the common attachments filter."
        ),
    )


def evaluate_mdo_malware_zap(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    return _bool_flag_result(
        surface_name="anti_malware",
        prop_name="ZapEnabled",
        flag=_flag(bundle, "anti_malware", "ZapEnabled"),
        ok_summary="Zero-hour auto purge (ZAP) is enabled for malware.",
        ok_customer="Delivered malware is automatically pulled back when detected.",
        gap_summary="Zero-hour auto purge is not enabled.",
        gap_customer=(
            "Emails that turn out to be malware stay in inboxes after detection. "
            "Enable zero-hour auto purge."
        ),
    )


def _safe_attachments_block(bundle: Any) -> bool | None:
    if not usable(bundle, _THREAT, "safe_attachments"):
        return None
    from licenselens.evaluators.exchange_lib import enabled_items

    selected = enabled_items(bundle, _THREAT, "safe_attachments")
    if not selected:
        return None
    return any(str(prop(item, "Action") or "").lower() in _BLOCK_ACTIONS for item in selected)


def evaluate_mdo_safe_attachments_block(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    flag = _safe_attachments_block(bundle)
    return _bool_flag_result(
        surface_name="safe_attachments",
        prop_name="Action",
        flag=flag,
        ok_summary="Safe Attachments is set to block or replace detected malware.",
        ok_customer="Suspicious attachments are blocked or removed before reaching users.",
        gap_summary="Safe Attachments is not set to a blocking action.",
        gap_customer=(
            "Suspicious attachments may still reach inboxes. Set Safe Attachments "
            "to block or dynamic delivery."
        ),
    )


def evaluate_mdo_safe_links_block_list(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    email = _flag(bundle, "safe_links", "EnableSafeLinksForEmail")
    teams = _flag(bundle, "safe_links", "EnableSafeLinksForTeams")
    office = _flag(bundle, "safe_links", "EnableSafeLinksForOffice")
    evidence_out = {
        "surface": "safe_links",
        "email": email,
        "teams": teams,
        "office": office,
    }
    if email is None and teams is None and office is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Safe Links block-list settings could not be read.",
            evidence=evidence_out,
            customer_summary="We could not confirm whether Safe Links screens URLs.",
            confidence=Confidence.MEDIUM,
            limitations=["Threat policy surface was not readable via PowerShell."],
        )
    missing = [
        name
        for name, flag in (("email", email), ("teams", teams), ("office", office))
        if flag is not True
    ]
    if not missing:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Safe Links block-list checks cover email, Teams, and Office apps.",
            evidence=evidence_out,
            customer_summary="Links in email, Teams, and Office apps are screened.",
            **direct_meta(),
        )
    if email is True:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"Safe Links block-list is incomplete for: {', '.join(missing)}.",
            evidence=evidence_out,
            customer_summary=(
                "Safe Links covers email but not every collaboration surface. "
                "Enable it for Teams and Office apps too."
            ),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Safe Links block-list checks are not enabled for email.",
        evidence=evidence_out,
        customer_summary="Email links are not screened. Turn on Safe Links for email.",
        **direct_meta(),
    )


def evaluate_mdo_safe_links_real_time_scan(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    return _bool_flag_result(
        surface_name="safe_links",
        prop_name="ScanUrls",
        flag=_flag(bundle, "safe_links", "ScanUrls"),
        ok_summary="Safe Links performs real-time scanning of suspicious and download links.",
        ok_customer="Links pointing to files are scanned before delivery.",
        gap_summary="Real-time Safe Links scanning is not enabled.",
        gap_customer=(
            "Direct download links are not scanned in real time. Enable real-time URL scanning."
        ),
    )


def evaluate_mdo_safe_links_click_tracking(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    return _bool_flag_result(
        surface_name="safe_links",
        prop_name="TrackClicks",
        flag=_flag(bundle, "safe_links", "TrackClicks"),
        ok_summary="Safe Links click tracking is enabled.",
        ok_customer="You can see who clicked risky links after the fact.",
        gap_summary="Safe Links click tracking is not enabled.",
        gap_customer="Enable click tracking so risky clicks are recorded.",
    )


def _impersonation_flag(bundle: Any, prop_name: str) -> bool | None:
    return any_enabled_with(
        bundle, _THREAT, "impersonation", lambda item: prop_bool(item, prop_name)
    )


def evaluate_mdo_impersonation_users_protected(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    sensitive_users = [str(u) for u in (evidence.get("sensitive_users") or []) if u]
    if not sensitive_users:
        return Evaluation(
            status=FindingStatus.SKIPPED,
            summary="Sensitive user impersonation requires a profile list of sensitive accounts.",
            evidence={"sensitive_users": []},
            customer_summary=(
                "List your high-value accounts (executives, admins) in the profile "
                "to check user impersonation protection."
            ),
            confidence=Confidence.LOW,
        )
    bundle = exchange_bundle(evidence)
    flag = _impersonation_flag(bundle, "EnableTargetedUserProtection")
    evidence_out = {
        "surface": "impersonation",
        "sensitive_users_count": len(sensitive_users),
        "targeted_user_protection": flag,
    }
    if flag is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Anti-phish impersonation settings could not be read.",
            evidence=evidence_out,
            customer_summary="We could not confirm user impersonation protection.",
            confidence=Confidence.MEDIUM,
            limitations=["Anti-phish surface was not readable via PowerShell."],
        )
    if flag:
        return Evaluation(
            status=FindingStatus.OK,
            summary="User impersonation protection is enabled for sensitive accounts.",
            evidence=evidence_out,
            customer_summary="Look-alike senders targeting your key people are flagged.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="User impersonation protection is not enabled for sensitive accounts.",
        evidence=evidence_out,
        customer_summary=(
            "Attackers can impersonate your executives without detection. "
            "Enable user impersonation protection for sensitive accounts."
        ),
        **direct_meta(),
    )


def evaluate_mdo_impersonation_domains_owned(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    flag = _impersonation_flag(bundle, "EnableOrganizationDomainsProtection")
    if flag is None:
        flag = _impersonation_flag(bundle, "EnableTargetedDomainsProtection")
    return _bool_flag_result(
        surface_name="impersonation",
        prop_name="EnableOrganizationDomainsProtection",
        flag=flag,
        ok_summary="Domain impersonation protection is enabled for owned domains.",
        ok_customer="Look-alike domains are caught before they fool your users.",
        gap_summary="Domain impersonation protection for owned domains is not enabled.",
        gap_customer=(
            "Spoofed versions of your own domains are not flagged. "
            "Enable domain impersonation protection."
        ),
    )


def evaluate_mdo_impersonation_partner_domains(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    partner_domains = [str(d) for d in (evidence.get("sensitive_domains") or []) if d]
    if not partner_domains:
        return Evaluation(
            status=FindingStatus.SKIPPED,
            summary="Partner-domain impersonation requires a profile list of partner domains.",
            evidence={"partner_domains": []},
            customer_summary=(
                "List your key partner domains in the profile to check their "
                "impersonation protection."
            ),
            confidence=Confidence.LOW,
        )
    bundle = exchange_bundle(evidence)
    flag = _impersonation_flag(bundle, "EnableTargetedDomainsProtection")
    evidence_out = {
        "surface": "impersonation",
        "partner_domains_count": len(partner_domains),
        "targeted_domain_protection": flag,
    }
    if flag is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Anti-phish impersonation settings could not be read.",
            evidence=evidence_out,
            customer_summary="We could not confirm partner-domain impersonation protection.",
            confidence=Confidence.MEDIUM,
            limitations=["Anti-phish surface was not readable via PowerShell."],
        )
    if flag:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Domain impersonation protection is enabled for partner domains.",
            evidence=evidence_out,
            customer_summary="Look-alike partner domains are flagged.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Domain impersonation protection for partner domains is not enabled.",
        evidence=evidence_out,
        customer_summary=(
            "Spoofed partner domains are not flagged. Enable targeted domain "
            "impersonation protection."
        ),
        **direct_meta(),
    )


_SAFETY_TIP_PROPS: Final = (
    "EnableFirstContactSafetyTips",
    "EnableSimilarUsersSafetyTips",
    "EnableSimilarDomainsSafetyTips",
    "EnableUnusualCharactersSafetyTips",
)


def evaluate_mdo_safety_tips_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _THREAT, "anti_phish"):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Anti-phish safety-tip settings could not be read.",
            evidence={"surface": "anti_phish", "readable": False},
            customer_summary="We could not confirm whether safety tips are shown.",
            confidence=Confidence.MEDIUM,
            limitations=["Anti-phish surface was not readable via PowerShell."],
        )
    from licenselens.evaluators.exchange_lib import enabled_items

    selected = enabled_items(bundle, _THREAT, "anti_phish")
    if not selected:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No enabled anti-phish policy was found.",
            evidence={"surface": "anti_phish", "policies": 0},
            customer_summary="We found no anti-phish policy to check safety tips on.",
            confidence=Confidence.MEDIUM,
            limitations=["No enabled anti-phish policy returned."],
        )
    item = selected[0]
    enabled_tips = [tip for tip in _SAFETY_TIP_PROPS if prop_bool(item, tip)]
    evidence_out = {"surface": "anti_phish", "enabled_safety_tips": enabled_tips}
    if len(enabled_tips) == len(_SAFETY_TIP_PROPS):
        return Evaluation(
            status=FindingStatus.OK,
            summary="All anti-phish safety tips are enabled.",
            evidence=evidence_out,
            customer_summary="Users see warnings for unusual and look-alike senders.",
            **direct_meta(),
        )
    if enabled_tips:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"Only {len(enabled_tips)} of {len(_SAFETY_TIP_PROPS)} safety tips enabled.",
            evidence=evidence_out,
            customer_summary="Some sender warnings are on, but not all. Review safety tips.",
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No anti-phish safety tips are enabled.",
        evidence=evidence_out,
        customer_summary=(
            "Users get no warning about unusual or look-alike senders. Enable safety tips."
        ),
        **direct_meta(),
    )

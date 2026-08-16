"""Impersonation and safety-tips threat-policy evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    any_enabled_with,
    direct_meta,
    exchange_bundle,
    prop_bool,
    usable,
)
from licenselens.evaluators.security_suite_threat_lib import THREAT, bool_flag_result
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_SAFETY_TIP_PROPS: Final = (
    "EnableFirstContactSafetyTips",
    "EnableSimilarUsersSafetyTips",
    "EnableSimilarDomainsSafetyTips",
    "EnableUnusualCharactersSafetyTips",
)


def _impersonation_flag(bundle: Any, prop_name: str) -> bool | None:
    return any_enabled_with(
        bundle, THREAT, "impersonation", lambda item: prop_bool(item, prop_name)
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
            summary="Sensitive user impersonation requires a configured list of sensitive accounts.",
            evidence={"sensitive_users": []},
            customer_summary=(
                "List your high-value accounts (executives, admins) in your configured "
                "settings to check user impersonation protection."
            ),
            confidence=Confidence.LOW,
        )
    bundle = exchange_bundle(evidence)
    flag_value = _impersonation_flag(bundle, "EnableTargetedUserProtection")
    evidence_out = {
        "surface": "impersonation",
        "sensitive_users_count": len(sensitive_users),
        "targeted_user_protection": flag_value,
    }
    if flag_value is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Anti-phish impersonation settings could not be read.",
            evidence=evidence_out,
            customer_summary="We could not confirm user impersonation protection.",
            confidence=Confidence.MEDIUM,
            limitations=["Anti-phish surface was not readable via PowerShell."],
        )
    if flag_value:
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
    flag_value = _impersonation_flag(bundle, "EnableOrganizationDomainsProtection")
    if flag_value is None:
        flag_value = _impersonation_flag(bundle, "EnableTargetedDomainsProtection")
    return bool_flag_result(
        surface_name="impersonation",
        prop_name="EnableOrganizationDomainsProtection",
        flag_value=flag_value,
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
            summary="Partner-domain impersonation requires a configured list of partner domains.",
            evidence={"partner_domains": []},
            customer_summary=(
                "List your key partner domains in your configured settings to check "
                "their impersonation protection."
            ),
            confidence=Confidence.LOW,
        )
    bundle = exchange_bundle(evidence)
    flag_value = _impersonation_flag(bundle, "EnableTargetedDomainsProtection")
    evidence_out = {
        "surface": "impersonation",
        "partner_domains_count": len(partner_domains),
        "targeted_domain_protection": flag_value,
    }
    if flag_value is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Anti-phish impersonation settings could not be read.",
            evidence=evidence_out,
            customer_summary="We could not confirm partner-domain impersonation protection.",
            confidence=Confidence.MEDIUM,
            limitations=["Anti-phish surface was not readable via PowerShell."],
        )
    if flag_value:
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


def evaluate_mdo_safety_tips_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, THREAT, "anti_phish"):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Anti-phish safety-tip settings could not be read.",
            evidence={"surface": "anti_phish", "readable": False},
            customer_summary="We could not confirm whether safety tips are shown.",
            confidence=Confidence.MEDIUM,
            limitations=["Anti-phish surface was not readable via PowerShell."],
        )
    from licenselens.evaluators.exchange_lib import enabled_items

    selected = enabled_items(bundle, THREAT, "anti_phish")
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

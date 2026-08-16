"""Exchange forwarding and SMTP AUTH evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.collectors.exchange_models import PolicyItem
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    direct_meta,
    exchange_bundle,
    items,
    prop,
    prop_bool,
    surface,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

PARTIAL_META: Final = {
    "confidence": Confidence.MEDIUM,
    "limitations": ["Surface was not readable via Exchange Online PowerShell; verify in portal."],
}


def unavailable(
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
        **PARTIAL_META,
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
        return unavailable(
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
            summary=("Automatic forwarding is limited to your approved external domains only."),
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
        return unavailable(
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

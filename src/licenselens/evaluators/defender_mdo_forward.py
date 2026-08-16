"""MDO outbound-forwarding, mailbox-intelligence, and transport-rule evaluators.

All three read direct Exchange Online PowerShell evidence (the exchange bundle)
collected by the ``exo_threat_policies`` and ``exo_transport`` adapters.
"""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    direct_meta,
    enabled_items,
    exchange_bundle,
    items,
    prop,
    prop_bool,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_THREAT = "exo_threat_policies"
_TRANSPORT = "exo_transport"
_ACCEPTED = "exo_accepted_domains"


def _unreadable(surface_name: str, customer_summary: str) -> Evaluation:
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=f"Surface '{surface_name}' could not be read via Exchange Online PowerShell.",
        evidence={"surface": surface_name, "readable": False},
        customer_summary=customer_summary,
        confidence=Confidence.MEDIUM,
        limitations=["Exchange Online PowerShell surface was not readable; verify in portal."],
    )


def evaluate_mdo_outbound_spam_forwarding_block(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Tenant-wide outbound automatic forwarding must be blocked (AutoForwardingEnabled)."""
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _THREAT, "outbound_spam"):
        return _unreadable(
            "outbound_spam",
            "We could not confirm whether outbound automatic forwarding is blocked.",
        )
    selected = enabled_items(bundle, _THREAT, "outbound_spam")
    if not selected:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No outbound spam filter policy was returned.",
            evidence={"surface": "outbound_spam", "policies": 0},
            customer_summary="We found no outbound spam filter policy to check.",
            confidence=Confidence.MEDIUM,
            limitations=["No outbound spam filter policy returned."],
        )
    forwarding = [item for item in selected if prop_bool(item, "AutoForwardingEnabled")]
    evidence_out = {
        "surface": "outbound_spam",
        "policies": len(selected),
        "forwarding_enabled": [item.name for item in forwarding],
    }
    if forwarding:
        names = ", ".join(sorted(item.name for item in forwarding))
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"Outbound automatic forwarding is enabled on {names}.",
            evidence=evidence_out,
            customer_summary=(
                "Mail can be silently auto-forwarded outside your organization. "
                "Block outbound automatic forwarding in the outbound spam filter policy."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Outbound automatic forwarding is blocked tenant-wide.",
        evidence=evidence_out,
        customer_summary="Automatic mail forwarding to outside addresses is blocked.",
        **direct_meta(),
    )


def evaluate_mdo_mailbox_intelligence(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Anti-phish mailbox intelligence must be enabled across anti-phish policies."""
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _THREAT, "anti_phish"):
        return _unreadable(
            "anti_phish",
            "We could not confirm whether mailbox intelligence is enabled.",
        )
    selected = enabled_items(bundle, _THREAT, "anti_phish")
    if not selected:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No enabled anti-phish policy was found.",
            evidence={"surface": "anti_phish", "policies": 0},
            customer_summary="We found no anti-phish policy to check mailbox intelligence on.",
            confidence=Confidence.MEDIUM,
            limitations=["No enabled anti-phish policy returned."],
        )
    enabled = [item for item in selected if prop_bool(item, "EnableMailboxIntelligence")]
    missing = [item.name for item in selected if not prop_bool(item, "EnableMailboxIntelligence")]
    evidence_out = {
        "surface": "anti_phish",
        "policies": len(selected),
        "mailbox_intelligence_enabled": len(enabled),
        "mailbox_intelligence_missing": sorted(missing),
    }
    if len(enabled) == len(selected):
        return Evaluation(
            status=FindingStatus.OK,
            summary=(
                f"Mailbox intelligence is enabled across all {len(selected)} "
                "anti-phish policy(ies)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Mailbox intelligence learns your senders so look-alike "
                "impersonation is caught."
            ),
            **direct_meta(),
        )
    if enabled:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Mailbox intelligence is off on {', '.join(sorted(missing))} "
                f"({len(enabled)} of {len(selected)} policies have it on)."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Mailbox intelligence is only partially on. Users covered by the "
                "other anti-phish policies miss impersonation detection."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Mailbox intelligence is disabled on every anti-phish policy.",
        evidence=evidence_out,
        customer_summary=(
            "Anti-phish policies are not learning your senders, so look-alike "
            "impersonation goes undetected. Enable mailbox intelligence."
        ),
        **direct_meta(),
    )


def _as_addresses(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _domain_of(address: str) -> str:
    lowered = address.strip().lower()
    if "@" in lowered:
        return lowered.rsplit("@", 1)[1]
    return lowered


def _accepted_domains(bundle: Any) -> set[str] | None:
    if not usable(bundle, _ACCEPTED, "accepted_domains"):
        return None
    domains = {
        _domain_of(str(prop(item, "DomainName") or ""))
        for item in items(bundle, _ACCEPTED, "accepted_domains")
    }
    return {d for d in domains if d} or None


def evaluate_mdo_transport_rule_external_forward(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """No enabled transport rule may Bcc/redirect mail to external domains."""
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _TRANSPORT, "transport_rules"):
        return _unreadable(
            "transport_rules",
            "We could not confirm whether transport rules forward mail externally.",
        )
    rules = enabled_items(bundle, _TRANSPORT, "transport_rules")
    accepted = _accepted_domains(bundle)

    suspects: list[tuple[str, list[str]]] = []
    unresolved: list[str] = []
    for item in rules:
        targets: list[str] = []
        for key in ("RedirectMessageTo", "BlindCopyTo"):
            targets.extend(_as_addresses(prop(item, key)))
        if not targets:
            continue
        if accepted is None:
            unresolved.append(item.name)
            continue
        external = sorted({t for t in targets if _domain_of(t) not in accepted})
        if external:
            suspects.append((item.name, external))

    evidence_out = {
        "surface": "transport_rules",
        "rules": len(rules),
        "accepted_domains": sorted(accepted) if accepted is not None else None,
        "external_forward_rules": [name for name, _ in suspects],
        "unresolved_rules": sorted(unresolved),
    }
    if unresolved and not suspects:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "Accepted domains could not be read, so forwarding on "
                f"{', '.join(sorted(unresolved))} could not be classified."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some transport rules forward mail somewhere, but we could not "
                "confirm the destination is internal. Review them in the portal."
            ),
            confidence=Confidence.MEDIUM,
            limitations=["Accepted domains surface was not readable via PowerShell."],
        )
    if suspects:
        named = "; ".join(
            f"{name} -> {', '.join(targets)}" for name, targets in sorted(suspects)
        )
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"Transport rule(s) forward or Bcc mail to external addresses: {named}.",
            evidence=evidence_out,
            customer_summary=(
                "A mail-flow rule quietly copies or redirects mail outside your "
                "organization. Remove it or scope it to internal recipients."
            ),
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="No transport rule forwards or Bcc's mail to external domains.",
        evidence=evidence_out,
        customer_summary="Mail-flow rules do not silently copy or redirect mail outside.",
        **direct_meta(),
    )


__all__ = [
    "evaluate_mdo_outbound_spam_forwarding_block",
    "evaluate_mdo_mailbox_intelligence",
    "evaluate_mdo_transport_rule_external_forward",
]

"""Email-authentication evaluators (DKIM via PowerShell, SPF/DMARC via DNS)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.exchange_models import PolicyItem
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    direct_meta,
    exchange_bundle,
    items,
    prop_bool,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_DNS_SOURCE = "DNS TXT resolution (system resolver)"


def evaluate_exo_dkim_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, "exo_dkim", "dkim"):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="DKIM signing configuration could not be read; treated as unresolved.",
            evidence={"surface": "dkim", "adapter": "exo_dkim", "readable": False},
            customer_summary="We could not confirm whether DKIM signing is turned on.",
            confidence=Confidence.MEDIUM,
            limitations=["DKIM surface was not readable via Exchange Online PowerShell."],
        )
    configs: list[PolicyItem] = items(bundle, "exo_dkim", "dkim")
    if not configs:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No DKIM signing configurations were returned.",
            evidence={"dkim_configs": 0},
            customer_summary="We found no DKIM records; verify DKIM signing per domain.",
            confidence=Confidence.MEDIUM,
            limitations=["Empty DKIM inventory; cannot confirm all domains are signed."],
        )
    disabled = [item.name for item in configs if prop_bool(item, "Enabled") is False]
    evidence_out = {"dkim_configs": len(configs), "disabled_domains": disabled}
    if disabled:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"DKIM signing is disabled for {len(disabled)} domain(s): {', '.join(disabled)}."
            ),
            evidence=evidence_out,
            customer_summary="Not all of your domains are DKIM-signed. Enable it for each.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="DKIM signing is enabled for all returned domains.",
        evidence=evidence_out,
        customer_summary="Your domains sign outgoing mail with DKIM.",
        **direct_meta(),
    )


def _dns_records(evidence: dict[str, Any]) -> dict[str, Any]:
    raw = evidence.get("dns_records") or {}
    if not isinstance(raw, dict):
        return {}
    records = raw.get("records") or {}
    return records if isinstance(records, dict) else {}


def _spf_missing(records: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for domain, state in records.items():
        spf = (state or {}).get("spf") or {}
        if not spf.get("present") or not spf.get("hard_fail"):
            missing.append(domain)
    return missing


def _dmarc_missing(records: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for domain, state in records.items():
        dmarc = (state or {}).get("dmarc") or {}
        if not dmarc.get("present"):
            missing.append(domain)
    return missing


def _dmarc_non_reject(records: dict[str, Any]) -> list[str]:
    weak: list[str] = []
    for domain, state in records.items():
        dmarc = (state or {}).get("dmarc") or {}
        if dmarc.get("present") and str(dmarc.get("policy") or "").lower() != "reject":
            weak.append(domain)
    return weak


def _no_domains(records: dict[str, Any]) -> bool:
    return not records


def evaluate_exo_spf_published(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    records = _dns_records(evidence)
    evidence_out = {"domains_checked": sorted(records), "spf_missing": []}
    if _no_domains(records):
        return Evaluation(
            status=FindingStatus.SKIPPED,
            summary="No tenant-owned custom domains were available for SPF checks.",
            evidence=evidence_out,
            customer_summary="No custom domains detected, so SPF could not be assessed.",
            confidence=Confidence.LOW,
        )
    missing = _spf_missing(records)
    evidence_out["spf_missing"] = sorted(missing)
    meta = dict(confidence=Confidence.HIGH, data_sources=[_DNS_SOURCE], limitations=[])
    if missing:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"SPF is missing or fails to reject unapproved senders for: "
                f"{', '.join(sorted(missing))}."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some of your domains lack a strict SPF record, so attackers can "
                "forge mail that looks like it came from you."
            ),
            **meta,
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Every assessed domain publishes an SPF record that fails unapproved senders.",
        evidence=evidence_out,
        customer_summary="Your domains publish strict SPF records.",
        **meta,
    )


def _dmarc_gap_check(
    *,
    evidence: dict[str, Any],
    selector: str,
    weak: list[str],
    summary_gap: str,
    customer_gap: str,
    summary_ok: str,
    customer_ok: str,
) -> Evaluation:
    records = _dns_records(evidence)
    evidence_out = {"domains_checked": sorted(records), selector: sorted(weak)}
    if _no_domains(records):
        return Evaluation(
            status=FindingStatus.SKIPPED,
            summary="No tenant-owned custom domains were available for DMARC checks.",
            evidence=evidence_out,
            customer_summary="No custom domains detected, so DMARC could not be assessed.",
            confidence=Confidence.LOW,
        )
    meta = dict(confidence=Confidence.HIGH, data_sources=[_DNS_SOURCE], limitations=[])
    if weak:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=summary_gap.format(domains=", ".join(sorted(weak))),
            evidence=evidence_out,
            customer_summary=customer_gap,
            **meta,
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=summary_ok,
        evidence=evidence_out,
        customer_summary=customer_ok,
        **meta,
    )


def evaluate_exo_dmarc_published(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return _dmarc_gap_check(
        evidence=evidence,
        selector="dmarc_missing",
        weak=_dmarc_missing(_dns_records(evidence)),
        summary_gap="DMARC is not published for: {domains}.",
        customer_gap=(
            "Some of your domains have no DMARC record, so receivers cannot tell "
            "what to do with mail that fails authentication."
        ),
        summary_ok="Every assessed domain publishes a DMARC record.",
        customer_ok="Your domains publish DMARC records.",
    )


def evaluate_exo_dmarc_reject(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    records = _dns_records(evidence)
    weak = sorted(set(_dmarc_missing(records)) | set(_dmarc_non_reject(records)))
    return _dmarc_gap_check(
        evidence=evidence,
        selector="dmarc_not_reject",
        weak=weak,
        summary_gap="DMARC is missing or not set to reject for: {domains}.",
        customer_gap=(
            "Some domains use a weaker DMARC policy than reject, so spoofed mail "
            "may still reach inboxes."
        ),
        summary_ok="Every assessed domain publishes DMARC with a reject policy.",
        customer_ok="Your domains reject mail that fails authentication.",
    )


def _contact_missing(records: dict[str, Any], contact: str) -> list[str]:
    target = contact.strip().lower()
    missing: list[str] = []
    for domain, state in records.items():
        dmarc = (state or {}).get("dmarc") or {}
        if not dmarc.get("present"):
            missing.append(domain)
            continue
        addresses = {str(a).lower() for a in [*dmarc.get("rua", []), *dmarc.get("ruf", [])]}
        if target not in addresses:
            missing.append(domain)
    return missing


def _profile_contact_check(
    *,
    evidence: dict[str, Any],
    contact: str,
    field: str,
    missing_summary: str,
    customer_missing: str,
) -> Evaluation:
    records = _dns_records(evidence)
    if not contact.strip():
        return Evaluation(
            status=FindingStatus.SKIPPED,
            summary=f"No {field} contact configured in the assessment profile.",
            evidence={"configured": False, "field": field},
            customer_summary="Provide the contact in your profile to check this DMARC field.",
            confidence=Confidence.LOW,
        )
    if _no_domains(records):
        return Evaluation(
            status=FindingStatus.SKIPPED,
            summary="No tenant-owned custom domains were available for DMARC checks.",
            evidence={"configured": True, "field": field},
            customer_summary="No custom domains detected, so DMARC could not be assessed.",
            confidence=Confidence.LOW,
        )
    missing = _contact_missing(records, contact)
    meta = dict(confidence=Confidence.HIGH, data_sources=[_DNS_SOURCE], limitations=[])
    if missing:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=missing_summary.format(domains=", ".join(sorted(missing))),
            evidence={"field": field, "contact": contact, "missing": sorted(missing)},
            customer_summary=customer_missing,
            **meta,
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"DMARC {field} contact is present for every assessed domain.",
        evidence={"field": field, "contact": contact, "missing": []},
        customer_summary=f"Your DMARC {field} contact is configured everywhere.",
        **meta,
    )


def evaluate_exo_dmarc_agency_contact(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    contact = str(evidence.get("dmarc_agency_contact") or "")
    return _profile_contact_check(
        evidence=evidence,
        contact=contact,
        field="agency",
        missing_summary="DMARC agency report contact is missing for: {domains}.",
        customer_missing=(
            "Add an internal mailbox to DMARC aggregate/failure reports so someone "
            "actually reads spoofing alerts."
        ),
    )


def evaluate_exo_dmarc_federal_contact(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    contact = str(evidence.get("dmarc_federal_contact") or "")
    return _profile_contact_check(
        evidence=evidence,
        contact=contact,
        field="federal",
        missing_summary="DMARC federal report contact is missing for: {domains}.",
        customer_missing=(
            "Add the required federal aggregate-report mailbox to DMARC for your domains."
        ),
    )

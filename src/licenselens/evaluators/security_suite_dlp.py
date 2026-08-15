"""Security Suite DLP and unified-audit evaluators (SCC PowerShell surfaces)."""

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
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_SCC = "scc_compliance"
_DLP_WORKLOADS: Final = frozenset(
    {"exchange", "sharepoint", "onedrive", "teams", "devices", "onedriveforbusiness"}
)


def _enabled_dlp_policies(bundle: Any) -> list[PolicyItem]:
    return [
        item
        for item in items(bundle, _SCC, "dlp_policies")
        if str(prop(item, "Mode") or "").strip().lower() == "enable"
    ]


def _dlp_unavailable(*, summary: str, customer: str) -> Evaluation:
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=summary,
        evidence={"surface": "dlp_policies", "adapter": _SCC, "readable": False},
        customer_summary=customer,
        confidence=Confidence.MEDIUM,
        limitations=["DLP surfaces were not readable via Security & Compliance PowerShell."],
    )


def evaluate_pur_dlp_policy_present(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _SCC, "dlp_policies"):
        return _dlp_unavailable(
            summary="DLP policy state could not be read; treated as unresolved.",
            customer="We could not confirm whether any DLP policy protects sensitive data.",
        )
    enabled = _enabled_dlp_policies(bundle)
    evidence_out = {
        "dlp_policy_count": len(items(bundle, _SCC, "dlp_policies")),
        "enforced_dlp_policies": len(enabled),
    }
    meta = dict(
        confidence=Confidence.HIGH,
        data_sources=[_SCC],
        limitations=[
            "Sensitive-information-type coverage (SSN/ITIN/credit card) is not "
            "enumerated; verify rule content in the Purview portal."
        ],
    )
    if enabled:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"{len(enabled)} DLP polic(y/ies) are enforced.",
            evidence=evidence_out,
            customer_summary="At least one DLP policy is actively protecting sensitive data.",
            **meta,
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No enforced DLP policy protects sensitive information.",
        evidence=evidence_out,
        customer_summary=(
            "Sensitive data (credit cards, tax IDs, social security numbers) is not "
            "protected by an enforced DLP policy."
        ),
        **meta,
    )


def evaluate_pur_dlp_locations_complete(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _SCC, "dlp_policies"):
        return _dlp_unavailable(
            summary="DLP policy locations could not be read; treated as unresolved.",
            customer="We could not confirm where DLP policies apply.",
        )
    workloads: set[str] = set()
    for item in _enabled_dlp_policies(bundle):
        value = prop(item, "Workload")
        if isinstance(value, str):
            workloads.add(value.strip().lower())
        elif isinstance(value, list):
            workloads.update(str(v).strip().lower() for v in value)
    covered = workloads & _DLP_WORKLOADS
    evidence_out = {"workloads": sorted(workloads), "covered_workloads": sorted(covered)}
    meta = dict(
        confidence=Confidence.HIGH,
        data_sources=[_SCC],
        limitations=[
            "Per-location coverage is derived from policy workload flags, not a "
            "full location enumeration."
        ],
    )
    if len(covered) >= 3:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"DLP policies span {len(covered)} workload locations.",
            evidence=evidence_out,
            customer_summary="DLP protection covers several of your key data locations.",
            **meta,
        )
    if covered:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"DLP policies cover only {len(covered)} workload location(s).",
            evidence=evidence_out,
            customer_summary=(
                "DLP is not applied across Exchange, OneDrive, SharePoint, and Teams. "
                "Broaden policy locations."
            ),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No DLP policy workload locations could be determined.",
        evidence=evidence_out,
        customer_summary="We could not find DLP policies covering your data locations.",
        **meta,
    )


def _dlp_rules(bundle: Any) -> list[PolicyItem]:
    return [
        item for item in items(bundle, _SCC, "dlp_rules") if prop_bool(item, "Disabled") is False
    ]


def evaluate_pur_dlp_enforcement_block(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _SCC, "dlp_rules"):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="DLP rule enforcement could not be read; treated as unresolved.",
            evidence={"surface": "dlp_rules", "adapter": _SCC, "readable": False},
            customer_summary="We could not confirm whether DLP blocks sharing sensitive data.",
            confidence=Confidence.MEDIUM,
            limitations=["DLP rules were not readable via Security & Compliance PowerShell."],
        )
    blocking = [item for item in _dlp_rules(bundle) if prop_bool(item, "BlockAccess")]
    evidence_out = {
        "dlp_rules": len(items(bundle, _SCC, "dlp_rules")),
        "blocking_rules": len(blocking),
    }
    if blocking:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"{len(blocking)} DLP rule(s) block sharing sensitive information.",
            evidence=evidence_out,
            customer_summary="DLP blocks sensitive data from being shared with everyone.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No DLP rule blocks sharing sensitive information.",
        evidence=evidence_out,
        customer_summary=(
            "Sensitive data can still be shared broadly. Add a DLP rule that blocks access."
        ),
        **direct_meta(),
    )


def evaluate_pur_dlp_notifications(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, _SCC, "dlp_rules"):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="DLP notification settings could not be read; treated as unresolved.",
            evidence={"surface": "dlp_rules", "adapter": _SCC, "readable": False},
            customer_summary="We could not confirm whether DLP notifies users.",
            confidence=Confidence.MEDIUM,
            limitations=["DLP rules were not readable via Security & Compliance PowerShell."],
        )
    notifying = [item for item in _dlp_rules(bundle) if prop_bool(item, "NotifyUser")]
    evidence_out = {
        "dlp_rules": len(items(bundle, _SCC, "dlp_rules")),
        "notifying_rules": len(notifying),
    }
    if notifying:
        return Evaluation(
            status=FindingStatus.OK,
            summary=f"{len(notifying)} DLP rule(s) notify users about sensitive data.",
            evidence=evidence_out,
            customer_summary="Users get educated when they handle sensitive data.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="DLP user notifications are not enabled.",
        evidence=evidence_out,
        customer_summary=(
            "Users get no guidance when they touch sensitive data. Enable DLP notifications."
        ),
        **direct_meta(),
    )


def evaluate_mdo_unified_audit_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    flag: bool | None = None
    adapter = _SCC
    if usable(bundle, _SCC, "audit_config"):
        flag = _audit_ingestion_flag(bundle, _SCC, "audit_config")
    if flag is None and usable(bundle, "exo_audit", "mailbox_audit"):
        adapter = "exo_audit"
        flag = _audit_ingestion_flag(bundle, "exo_audit", "mailbox_audit")
    evidence_out = {"adapter": adapter, "unified_audit_ingestion": flag}
    if flag is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Unified audit logging state could not be read; treated as unresolved.",
            evidence=evidence_out,
            customer_summary="We could not confirm whether unified audit logging is on.",
            confidence=Confidence.MEDIUM,
            limitations=["Unified audit ingestion was not readable via PowerShell."],
        )
    if flag:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Unified audit logging is enabled.",
            evidence=evidence_out,
            customer_summary="User and admin activity is being recorded for investigation.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Unified audit logging is not enabled.",
        evidence=evidence_out,
        customer_summary=(
            "Activity across Microsoft 365 is not being recorded. Turn on unified audit logging."
        ),
        **direct_meta(),
    )


def _audit_ingestion_flag(bundle: Any, adapter: str, name: str) -> bool | None:
    rows = items(bundle, adapter, name)
    if not rows:
        return None
    return prop_bool(rows[0], "UnifiedAuditLogIngestionEnabled")

"""Shared helpers for Defender for Office threat-policy evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import any_enabled_with, direct_meta, prop_bool
from licenselens.models import Confidence, FindingStatus

THREAT = "exo_threat_policies"
BLOCK_ACTIONS: Final = frozenset({"block", "dynamicdelivery", "replace", "remove"})


def flag(bundle: Any, surface_name: str, prop_name: str) -> bool | None:
    return any_enabled_with(bundle, THREAT, surface_name, lambda item: prop_bool(item, prop_name))


def bool_flag_result(
    *,
    surface_name: str,
    prop_name: str,
    flag_value: bool | None,
    ok_summary: str,
    ok_customer: str,
    gap_summary: str,
    gap_customer: str,
    note: str = "",
) -> Evaluation:
    evidence_out = {"surface": surface_name, "property": prop_name, "value": flag_value}
    if note:
        evidence_out["note"] = note
    if flag_value is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"Threat policy surface '{surface_name}' could not be read.",
            evidence=evidence_out,
            customer_summary="We could not confirm this email protection from a direct read.",
            confidence=Confidence.MEDIUM,
            limitations=["Threat policy surface was not readable via PowerShell."],
        )
    if flag_value:
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

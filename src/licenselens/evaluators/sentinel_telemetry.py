"""Sentinel telemetry-ingestion and Entra-diagnostics (proxy) evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_RISK_TABLES = ("AADUserRiskEvents", "AADRiskyUsers")
_SIGNIN = "SigninLogs"
_ENTRA_LIMITATION = (
    "Inferred from workspace usage only — confirm Entra diagnostic settings "
    "(Entra admin center → Diagnostic settings) before treating this as definitive."
)


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _table_ingesting(detail: object, *, query_mode: bool) -> bool:
    if not isinstance(detail, dict):
        return not query_mode
    if not query_mode:
        return True
    rows = detail.get("rows") or 0
    mb = detail.get("total_mb") or 0
    try:
        return int(rows) > 0 or float(mb) > 0
    except (TypeError, ValueError):
        return False


def _usage_tables(evidence: dict[str, Any]) -> tuple[dict[str, Any], str, bool]:
    usage = _as_dict(evidence.get("la_usage_by_table"))
    mode = str(usage.get("mode") or "query")
    tables = _as_dict(usage.get("tables"))
    incomplete = bool(usage.get("required_surface_incomplete")) or mode == "table_list_only"
    return tables, mode, incomplete


def evaluate_sen_telemetry_ingestion_coverage(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    tables, mode, incomplete = _usage_tables(evidence)
    catalog = _as_dict(evidence.get("telemetry_expectations"))
    owned = {str(item) for item in (evidence.get("owned_capabilities") or [])}
    matrix: dict[str, Any] = {}
    for row in catalog.get("expectations") or []:
        if not isinstance(row, dict):
            continue
        cap_id = str(row.get("capability_id") or "")
        if cap_id not in owned:
            continue
        cores = [
            str(t.get("name"))
            for t in (row.get("tables") or [])
            if isinstance(t, dict) and t.get("tier") == "core" and t.get("name")
        ]
        extended = [
            str(t.get("name"))
            for t in (row.get("tables") or [])
            if isinstance(t, dict) and t.get("tier") == "extended" and t.get("name")
        ]
        query_mode = mode == "query" and not incomplete
        core_seen = [
            name
            for name in cores
            if name in tables and _table_ingesting(tables.get(name), query_mode=query_mode)
        ]
        extended_seen = [
            name
            for name in extended
            if name in tables and _table_ingesting(tables.get(name), query_mode=query_mode)
        ]
        missing = [name for name in cores if name not in core_seen]
        matrix[cap_id] = {
            "core_expected": cores,
            "core_seen": core_seen,
            "extended_seen": extended_seen,
            "missing_core": missing,
        }
    evidence_out = {"capabilities": matrix, "mode": mode}
    if incomplete:
        evidence_out["required_surface_incomplete"] = True

    if not matrix:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No owned capabilities with telemetry expectations were in scope.",
            evidence=evidence_out,
            customer_summary="We could not match owned protections to expected log tables.",
        )

    zero_core = [
        cap for cap, row in matrix.items() if row["core_expected"] and not row["core_seen"]
    ]
    missing_any = [cap for cap, row in matrix.items() if row["missing_core"]]
    if zero_core:
        status = FindingStatus.GAP
        summary = (
            "Owned capabilities have no core tables ingesting in the last 7 days: "
            + ", ".join(sorted(zero_core))
            + "."
        )
        customer = (
            "Some protections you already pay for are not sending their main logs "
            "into the security workspace."
        )
    elif missing_any:
        status = FindingStatus.PARTIAL
        summary = (
            "Some owned capabilities are missing core tables: "
            + ", ".join(sorted(missing_any))
            + "."
        )
        customer = "Log coverage for owned protections is incomplete."
    else:
        status = FindingStatus.OK
        summary = (
            "Core tables for every owned capability with expectations ingested in the last 7 days."
        )
        customer = "Expected security logs for owned protections are arriving in the workspace."

    if incomplete and status is FindingStatus.OK:
        status = FindingStatus.PARTIAL
        evidence_out["required_surface_incomplete"] = True
        summary = f"{summary.rstrip('.')} (table-list fallback only; not marked fully OK)."

    return Evaluation(
        status=status,
        summary=summary,
        evidence=evidence_out,
        customer_summary=customer,
        confidence=Confidence.LOW if incomplete else Confidence.HIGH,
        data_sources=["la:usageByTable"],
    )


def evaluate_sen_entra_diagnostics_routed(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    owned = {str(item) for item in (evidence.get("owned_capabilities") or [])}
    tables, mode, incomplete = _usage_tables(evidence)
    query_mode = mode == "query" and not incomplete
    checked = [_SIGNIN, *_RISK_TABLES]
    present = [
        name
        for name in checked
        if name in tables and _table_ingesting(tables.get(name), query_mode=query_mode)
    ]
    absent = [name for name in checked if name not in present]
    evidence_out = {
        "tables_checked": list(checked),
        "present": present,
        "absent": absent,
        "proxy": True,
        "mode": mode,
    }
    if "identity_protection" not in owned:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="Identity Protection is not owned; Entra risk-table routing was not assessed.",
            evidence=evidence_out,
            customer_summary="Identity Protection is not in the licenses we detected.",
            confidence=Confidence.LOW,
            data_sources=["la:usageByTable"],
            limitations=[_ENTRA_LIMITATION],
        )
    risk_present = [name for name in _RISK_TABLES if name in present]
    if not risk_present:
        status = FindingStatus.GAP
        summary = (
            "Neither AADUserRiskEvents nor AADRiskyUsers ingested in the last 7 days "
            "while Identity Protection is owned."
        )
        customer = (
            "Entra risk signals do not appear to be reaching the security workspace. "
            "Confirm diagnostic settings in Entra."
        )
    else:
        status = FindingStatus.PARTIAL
        summary = (
            "Entra tables are present in workspace usage; confirm diagnostic settings "
            "in the Entra admin center (proxy evidence, never fully OK)."
        )
        customer = (
            "Sign-in or risk logs appear to be arriving, but this is inferred from "
            "usage only — confirm the diagnostic-settings blade in Entra."
        )
    return Evaluation(
        status=status,
        summary=summary,
        evidence=evidence_out,
        customer_summary=customer,
        confidence=Confidence.LOW,
        data_sources=["la:usageByTable"],
        limitations=[_ENTRA_LIMITATION],
    )

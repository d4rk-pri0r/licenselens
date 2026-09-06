"""Sentinel rule ↔ telemetry parity evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.kql.table_refs import extract_table_refs
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_DEAD_CAP = 25


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _table_ingesting(detail: object, *, query_mode: bool) -> bool:
    if not isinstance(detail, dict):
        return not query_mode
    if not query_mode:
        return True
    try:
        rows = int(detail.get("rows") or 0)
        mb = float(detail.get("total_mb") or 0)
    except (TypeError, ValueError):
        return False
    return rows > 0 or mb > 0


def _known_tables(evidence: dict[str, Any]) -> frozenset[str]:
    names: set[str] = set()
    catalog = _as_dict(evidence.get("telemetry_expectations"))
    for row in catalog.get("expectations") or []:
        if not isinstance(row, dict):
            continue
        for table in row.get("tables") or []:
            if isinstance(table, dict) and table.get("name"):
                names.add(str(table["name"]))
    usage = _as_dict(evidence.get("la_usage_by_table"))
    for name in _as_dict(usage.get("tables")):
        names.add(str(name))
    return frozenset(names)


def _iter_rule_queries(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rules = _as_dict(evidence.get("sentinel_rules"))
    for item in rules.get("rules_detail") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").lower()
        if kind not in {"scheduled", "nrt"}:
            continue
        if not item.get("enabled"):
            continue
        out.append(
            {
                "name": str(item.get("displayName") or "unnamed"),
                "query": str(item.get("query") or ""),
                "tactics": [str(t) for t in (item.get("tactics") or [])],
                "source": "sentinel",
            }
        )
    xdr = _as_dict(evidence.get("xdr_custom_detections"))
    for item in xdr.get("rules") or []:
        if not isinstance(item, dict) or not item.get("isEnabled"):
            continue
        out.append(
            {
                "name": str(item.get("displayName") or "unnamed"),
                "query": str(item.get("queryText") or ""),
                "tactics": [],
                "source": "xdr",
            }
        )
    return out


def evaluate_sen_rule_telemetry_parity(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    usage = _as_dict(evidence.get("la_usage_by_table"))
    tables = _as_dict(usage.get("tables"))
    mode = str(usage.get("mode") or "query")
    incomplete = bool(usage.get("required_surface_incomplete")) or mode == "table_list_only"
    query_mode = mode == "query" and not incomplete
    known = _known_tables(evidence)
    owned = {str(item) for item in (evidence.get("owned_capabilities") or [])}
    catalog = _as_dict(evidence.get("telemetry_expectations"))

    live = 0
    dead: list[dict[str, Any]] = []
    indeterminate = 0
    live_tactics: set[str] = set()
    live_table_refs: set[str] = set()
    truncated = False

    for rule in _iter_rule_queries(evidence):
        refs = extract_table_refs(rule["query"], known_tables=known)
        if refs.indeterminate:
            indeterminate += 1
            continue
        missing = [
            name
            for name in sorted(refs.tables)
            if name not in tables or not _table_ingesting(tables.get(name), query_mode=query_mode)
        ]
        if missing:
            if len(dead) < _DEAD_CAP:
                dead.append(
                    {
                        "name": rule["name"],
                        "missing_tables": missing,
                        "source": rule["source"],
                    }
                )
            else:
                truncated = True
            continue
        live += 1
        live_table_refs.update(refs.tables)
        live_tactics.update(rule["tactics"])

    evaluable = live + len(dead)
    ratio = (len(dead) / evaluable) if evaluable else 0.0

    ingesting_cores: list[str] = []
    for row in catalog.get("expectations") or []:
        if not isinstance(row, dict):
            continue
        cap_id = str(row.get("capability_id") or "")
        if cap_id not in owned:
            continue
        for table in row.get("tables") or []:
            if not isinstance(table, dict) or table.get("tier") != "core":
                continue
            name = str(table.get("name") or "")
            ingesting = name in tables and _table_ingesting(tables.get(name), query_mode=query_mode)
            if name and ingesting:
                ingesting_cores.append(name)
    unwatched = sorted({name for name in ingesting_cores if name not in live_table_refs})

    evidence_out: dict[str, Any] = {
        "dead_rules": dead,
        "dead_rules_truncated": truncated,
        "unwatched_tables": unwatched,
        "indeterminate_rules": indeterminate,
        "live_tactics": sorted(live_tactics),
        "evaluable_rules": evaluable,
        "dead_rule_ratio": ratio,
        "mode": mode,
    }
    if incomplete:
        evidence_out["required_surface_incomplete"] = True

    if ratio >= 0.25 or (unwatched and evaluable >= 3):
        status = FindingStatus.GAP
        summary = (
            f"{len(dead)} of {evaluable} evaluable rules reference tables that are not ingesting "
            f"(ratio {ratio:.2f})."
        )
        if unwatched:
            summary = summary.rstrip(".") + f"; unwatched core tables: {', '.join(unwatched)}."
        customer = (
            "Some detection rules watch logs that are not arriving, "
            "or expected logs have no live rule."
        )
    elif evaluable < 3:
        status = FindingStatus.PARTIAL
        summary = (
            f"Too few evaluable analytics rules to judge telemetry parity "
            f"({evaluable} evaluable, {len(dead)} dead)."
        )
        customer = (
            "There are not enough evaluable detection rules to confirm they match incoming logs."
        )
    elif dead or unwatched:
        status = FindingStatus.PARTIAL
        unwatched_label = ", ".join(unwatched) or "none"
        summary = (
            f"{len(dead)} evaluable rule(s) are dead; unwatched core tables: {unwatched_label}."
        )
        customer = "Detection-rule coverage of incoming logs is incomplete."
    else:
        status = FindingStatus.OK
        summary = (
            f"All {evaluable} evaluable rules reference ingesting tables; "
            "owned core tables are watched."
        )
        customer = "Enabled detection rules match the logs arriving in the workspace."

    if incomplete and status is FindingStatus.OK:
        status = FindingStatus.PARTIAL
        summary = f"{summary.rstrip('.')} (table-list fallback only; not marked fully OK)."

    return Evaluation(
        status=status,
        summary=summary,
        evidence=evidence_out,
        customer_summary=customer,
        confidence=Confidence.LOW if incomplete else Confidence.HIGH,
        data_sources=["la:usageByTable"],
    )


def dead_rule_ratio_from_evidence(evidence: dict[str, Any]) -> float | None:
    """Return dead/evaluable when rules_detail is present; else None."""
    rules = _as_dict(evidence.get("sentinel_rules"))
    if not isinstance(rules.get("rules_detail"), list):
        return None
    usage = _as_dict(evidence.get("la_usage_by_table"))
    tables = _as_dict(usage.get("tables"))
    mode = str(usage.get("mode") or "query")
    incomplete = bool(usage.get("required_surface_incomplete")) or mode == "table_list_only"
    query_mode = mode == "query" and not incomplete
    known = _known_tables(evidence)
    live = 0
    dead = 0
    for rule in _iter_rule_queries(evidence):
        refs = extract_table_refs(rule["query"], known_tables=known)
        if refs.indeterminate:
            continue
        missing = [
            name
            for name in refs.tables
            if name not in tables or not _table_ingesting(tables.get(name), query_mode=query_mode)
        ]
        if missing:
            dead += 1
        else:
            live += 1
    evaluable = live + dead
    if evaluable < 3:
        return None
    return dead / evaluable

"""Deterministic, testable view-model layer for the v2 report redesign.

Pure functions over :class:`~licenselens.models.ScanResult` that build plain-data
payloads consumed by the HTML template. The module performs no I/O, uses no
randomness, and imports no renderer — only :mod:`licenselens.models` plus the
standard library. Every function is a pure mapping from a ``ScanResult`` (or its
parts) to plain ``dict``/``list`` data, so identical input always yields
identical output.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Final

from licenselens.models import (
    CapabilityOutcome,
    CapabilitySummary,
    Finding,
    ScanResult,
)

# allow: SIZE_OK — shared view-model module; consumers (html.py, bundle.py,
# test_report_viewmodel.py, test_report_v2_contract.py) import builders from
# here, and the T3/T4 constraint forbids changing existing builder signatures,
# so the module is extended in place rather than split.

#: Fixed workload ordering for the capability constellation. Reuses the v1
#: renderer's ``_WORKLOAD_PRIORITY`` idea (identity first, then endpoint, then
#: the remaining workloads). Workloads absent from this tuple sort after every
#: listed workload.
_WORKLOAD_PRIORITY: Final[tuple[str, ...]] = (
    "identity",
    "endpoint",
    "defender",
    "sentinel",
    "purview",
    "exchange",
    "collaboration",
    "teams",
    "power_platform",
    "power_bi",
    "intune",
    "azure",
)

_WORKLOAD_RANK: Final[dict[str, int]] = {
    workload: rank for rank, workload in enumerate(_WORKLOAD_PRIORITY)
}


def build_posture(result: ScanResult) -> dict[str, int | str]:
    """Build the A-section posture figure from the capability rollup.

    Returns ``{"realized_percent": int, "realized_sentence": str}`` bound
    directly to ``result.capability_rollup.realized_percent`` and
    ``result.capability_rollup.realized_sentence``. No literal number is
    produced here; the value flows straight from the model.
    """
    rollup = result.capability_rollup
    return {
        "realized_percent": rollup.realized_percent,
        "realized_sentence": rollup.realized_sentence,
    }


#: Neutral tenant label when the scan carries no tenant display name to show.
_FALLBACK_TENANT_NAME: Final[str] = "Your tenant"


def build_opening(result: ScanResult) -> dict[str, object]:
    """Build the v2 signature-opening payload (org identity + assessment identity).

    Returns ``{"tenant_name": str, "tenant_id": str | None,
    "assessment_identity": dict, "scanned_at": str, "realized_percent": int,
    "realized_sentence": str}``:

    * ``tenant_name`` — ``result.tenant_display_name``; when the model carries no
      display name the neutral ``_FALLBACK_TENANT_NAME`` is returned, never
      ``None``. The raw ``tenant_id`` is surfaced separately under its own key so
      the renderer can show it as secondary context.
    * ``assessment_identity`` — the generator ``tool_display_name``, ``tool``,
      and ``version`` straight from the model.
    * ``scanned_at`` — the scan timestamp verbatim from the model.
    * ``realized_percent`` / ``realized_sentence`` — :func:`build_posture`
      output, so the opening count-up and implication derive from the exact same
      values as section A. No literal number is produced here.

    Deterministic: identical ``ScanResult`` in, identical dict out.
    """
    posture = build_posture(result)
    return {
        "tenant_name": result.tenant_display_name or _FALLBACK_TENANT_NAME,
        "tenant_id": result.tenant_id,
        "assessment_identity": {
            "tool": result.tool,
            "tool_display_name": result.tool_display_name,
            "version": result.version,
        },
        "scanned_at": result.scanned_at,
        "realized_percent": posture["realized_percent"],
        "realized_sentence": posture["realized_sentence"],
    }


def _primary_workload(result: ScanResult, outcome: CapabilityOutcome | None) -> str | None:
    """Pick the dominant related-finding workload for one capability.

    Mirrors the v1 renderer's workload heuristic: count the non-``general``
    workloads of the findings whose ``check_id`` appears in
    ``outcome.related_check_ids``, then pick the most frequent. Ties resolve
    through ``_WORKLOAD_PRIORITY`` order (then a byte sort of the remainder).
    Returns ``None`` when no related finding carries a workload.
    """
    if outcome is None or not outcome.related_check_ids:
        return None
    related = set(outcome.related_check_ids)
    counts: Counter[str] = Counter()
    for finding in result.findings:
        if finding.check_id not in related:
            continue
        value = finding.workload.value
        if value != "general":
            counts[value] += 1
    if not counts:
        return None
    best = max(counts.values())
    candidates = {workload for workload, count in counts.items() if count == best}
    for workload in _WORKLOAD_PRIORITY:
        if workload in candidates:
            return workload
    return sorted(candidates)[0]


def _workload_rank(workload: str | None) -> int:
    """Return the constellation sort rank for a workload (unknowns sort last)."""
    if workload is None:
        return len(_WORKLOAD_PRIORITY)
    return _WORKLOAD_RANK.get(workload, len(_WORKLOAD_PRIORITY))


def build_constellation(result: ScanResult) -> list[dict[str, str | int | None]]:
    """Build the capability constellation as a deterministically ordered list.

    One entry per :class:`~licenselens.models.CapabilityOutcome`, joined to its
    :class:`~licenselens.models.CapabilitySummary` by ``id``. Entries are ordered
    by workload priority (``_WORKLOAD_PRIORITY``) and then by ``plain_name`` byte
    sort for ties. No randomness: identical input yields an identical list.

    Each entry carries ``id``, ``name``, ``plain_name``, ``status``,
    ``status_label``, ``workload``, and ``related_check_ids`` (the count of
    related checks).
    """
    summary_by_id: dict[str, CapabilitySummary] = {
        summary.id: summary for summary in result.capability_summaries
    }
    ranked: list[tuple[int, str, dict[str, str | int | None]]] = []
    for outcome in result.capability_outcomes:
        summary = summary_by_id.get(outcome.id)
        workload = _primary_workload(result, outcome)
        name = summary.name if summary else outcome.name
        plain_name = summary.plain_name if summary else outcome.plain_name
        entry: dict[str, str | int | None] = {
            "id": outcome.id,
            "name": name,
            "plain_name": plain_name,
            "status": outcome.status,
            "status_label": outcome.status_label,
            "workload": workload,
            "related_check_ids": len(outcome.related_check_ids),
        }
        ranked.append((_workload_rank(workload), plain_name, entry))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [entry for _, _, entry in ranked]


def build_belief_block(
    finding: Finding,
    capability_summaries: list[CapabilitySummary],
) -> dict[str, object]:
    """Map one finding to its six D-section belief-block slots.

    Slot bindings (in fallback order):

    * ``expected`` — the matching capability's ``outcome``; empty string when no
      capability matches.
    * ``observed`` — ``finding.summary`` plus ``finding.evidence`` (a dict).
    * ``why_it_matters`` — the matching capability's ``why_it_matters`` plus the
      ``severity``/``value_impact``/``blast_radius`` enum values.
    * ``recommended_action`` — ``finding.customer_next_step`` else
      ``finding.remediation``.
    * ``evidence`` — ``finding.data_sources``, ``finding.confidence_label``, and
      ``finding.limitations``.
    * ``admin_destination`` — ``finding.deep_link`` (``None`` when absent).

    The "matching capability" is the first ``CapabilitySummary`` whose ``id``
    appears in ``finding.entitlements_used`` (the engine stores the check's owned
    ``required_capabilities`` there). When that list is empty or names no
    summary, the capability-dependent slots fall back to empty strings.
    """
    summary_by_id: dict[str, CapabilitySummary] = {
        summary.id: summary for summary in capability_summaries
    }
    matched: CapabilitySummary | None = None
    for capability_id in finding.entitlements_used:
        if capability_id in summary_by_id:
            matched = summary_by_id[capability_id]
            break
    return {
        "expected": matched.outcome if matched else "",
        "observed": {
            "summary": finding.summary,
            "evidence": finding.evidence,
        },
        "why_it_matters": {
            "capability": matched.why_it_matters if matched else "",
            "severity": finding.severity.value,
            "value_impact": finding.value_impact.value,
            "blast_radius": finding.blast_radius.value,
        },
        "recommended_action": finding.customer_next_step or finding.remediation,
        "evidence": {
            "data_sources": finding.data_sources,
            "confidence_label": finding.confidence_label,
            "limitations": finding.limitations,
        },
        "admin_destination": finding.deep_link,
    }


def _capability_entry(
    summary: CapabilitySummary,
    outcome: CapabilityOutcome | None,
) -> dict[str, object]:
    """Serialize one capability summary joined to its (optional) outcome."""
    return {
        "id": summary.id,
        "name": summary.name,
        "plain_name": summary.plain_name,
        "matched_skus": summary.matched_skus,
        "matched_service_plans": summary.matched_service_plans,
        "outcome": summary.outcome,
        "why_it_matters": summary.why_it_matters,
        "if_unused": summary.if_unused,
        "docs_url": summary.docs_url,
        "status": outcome.status if outcome else None,
        "status_label": outcome.status_label if outcome else None,
    }


def _finding_entry(finding: Finding) -> dict[str, object]:
    """Serialize one finding for the E-section list and its filter metadata."""
    return {
        "check_id": finding.check_id,
        "title": finding.display_customer_title,
        "status": finding.status.value,
        "status_label": finding.status_label,
        "severity": finding.severity.value,
        "value_impact": finding.value_impact.value,
        "effort": finding.effort.value,
        "effort_label": finding.effort_label,
        "blast_radius": finding.blast_radius.value,
        "workload": finding.workload.value,
        "pack": finding.pack.value,
        "confidence": finding.confidence.value,
        "confidence_label": finding.confidence_label,
        "evaluation_mode": finding.evaluation_mode.value,
        "exposure_class": finding.exposure_class.value,
        "deep_link": finding.deep_link,
        "summary": finding.summary,
        "customer_summary": finding.customer_summary,
        "customer_next_step": finding.customer_next_step,
        "remediation": finding.remediation,
        "evidence": finding.evidence,
        "data_sources": finding.data_sources,
        "limitations": finding.limitations,
    }


def _sorted_unique(values: Iterable[str]) -> list[str]:
    """Return the distinct values of an iterable, sorted deterministically."""
    return sorted(set(values))


def build_sections(result: ScanResult) -> dict[str, object]:
    """Build the A/B/C/D/E section payloads for the report template.

    * ``A`` — the posture figure plus the rollup counts (``you_own``,
      ``fully_working``, ``needs_attention``, ``partly_set_up``,
      ``not_licensed``).
    * ``B`` — one serialized ``CapabilitySummary`` per owned capability, joined
      with its outcome status and carrying ``matched_skus``,
      ``matched_service_plans``, and ``outcome``.
    * ``C`` — ``result.moves`` verbatim. The engine already caps the list at 3;
      this layer must not slice or reorder it.
    * ``D`` — one belief block per finding (see :func:`build_belief_block`).
    * ``E`` — the full findings list plus filter facet metadata (status,
      severity, confidence, evaluation mode, pack, workload), each facet the
      distinct values present in the findings, sorted deterministically.
    """
    rollup = result.capability_rollup
    outcome_by_id: dict[str, CapabilityOutcome] = {
        outcome.id: outcome for outcome in result.capability_outcomes
    }
    findings = result.findings
    return {
        "A": {
            "posture": build_posture(result),
            "rollup": {
                "you_own": rollup.you_own,
                "fully_working": rollup.fully_working,
                "needs_attention": rollup.needs_attention,
                "partly_set_up": rollup.partly_set_up,
                "not_licensed": rollup.not_licensed,
            },
        },
        "B": [
            _capability_entry(summary, outcome_by_id.get(summary.id))
            for summary in result.capability_summaries
        ],
        "C": result.moves,
        "D": [build_belief_block(finding, result.capability_summaries) for finding in findings],
        "E": {
            "findings": [_finding_entry(finding) for finding in findings],
            "filters": {
                "status": _sorted_unique(f.status.value for f in findings),
                "severity": _sorted_unique(f.severity.value for f in findings),
                "confidence": _sorted_unique(f.confidence.value for f in findings),
                "evaluation_mode": _sorted_unique(f.evaluation_mode.value for f in findings),
                "pack": _sorted_unique(f.pack.value for f in findings),
                "workload": _sorted_unique(f.workload.value for f in findings),
            },
        },
    }

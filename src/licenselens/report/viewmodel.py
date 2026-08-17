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

from licenselens.catalog.expected_states import expected_state_map
from licenselens.friendly_names import friendly_plan_name, friendly_sku_name
from licenselens.models import (
    CapabilityOutcome,
    CapabilitySummary,
    Finding,
    FindingStatus,
    ScanResult,
)

# allow: SIZE_OK — shared view-model module; consumers (html.py, bundle.py,
# test_report_viewmodel.py, test_report_v2_contract.py) import builders from
# here, and the T3/T4 constraint forbids changing existing builder signatures
# (the todo-7 ``expected_by_check_id`` threading is the one sanctioned
# extension), so the module is extended in place rather than split.

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

#: Exec-facing copy for enum facet values: facet name -> {raw value -> human
#: label}. Raw enum values stay untouched in the payload (JSON/view-model and
#: technical drill-down); only presentation surfaces (masthead, finding meta
#: rows, charts) consume these labels.
EXEC_COPY: Final[dict[str, dict[str, str]]] = {
    "scan_mode": {
        "dry_run": "Demo scan (synthetic data)",
        "live": "Live tenant scan",
    },
    "evaluation_mode": {
        "direct": "Read directly",
        "proxy": "Approximated — verify in portal",
        "manual": "Manual review",
        "direct_with_proxy_fallback": "Read directly (with fallback)",
        "unsupported": "Unsupported",
    },
    "scope": {
        "admin": "Administrator scope",
        "all_users": "All users",
        "devices": "All devices",
        "data": "Tenant data",
    },
    "value_impact": {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    },
}


def human_copy(facet: str, value: str | None) -> str:
    """Return the human presentation label for one raw enum facet value.

    Empty/``None`` values return ``""`` so renderers can omit the slot. Unknown
    values fall back to a light prettification (underscores become spaces, the
    first letter is capitalized) so a new enum member never surfaces raw.
    """
    if not value:
        return ""
    return EXEC_COPY.get(facet, {}).get(value, value.replace("_", " ").capitalize())


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

#: Zero-value tenant id that dry-run and sanitized-sample scans carry. It is
#: never rendered as org identity — a raw all-zero GUID in the hero reads as a
#: placeholder leak, not an identifier.
_ZERO_TENANT_ID: Final[str] = "00000000-0000-0000-0000-000000000000"

#: Clean org label for demo/dry-run renders: plain words, no internal jargon.
_DEMO_TENANT_NAME: Final[str] = "Demo (synthetic data)"

#: Legacy demo display names (the pre-1.0 dry-run default and older sanitized
#: samples) mapped to the clean demo label so historical fixtures and stale
#: scan artifacts stay presentable without a regeneration pass.
_LEGACY_DEMO_TENANT_NAMES: Final[frozenset[str]] = frozenset(
    {"Contoso Demo (dry-run)", "demo / dry-run"}
)


def build_opening(result: ScanResult) -> dict[str, object]:
    """Build the v2 signature-opening payload (org identity + assessment identity).

    Returns ``{"tenant_name": str, "tenant_id": str | None,
    "assessment_identity": dict, "scanned_at": str, "realized_percent": int,
    "realized_sentence": str}``:

    * ``tenant_name`` — the org identity for the hero. The tenant display name
      wins when real; legacy demo display names ("Contoso Demo (dry-run)" and
      friends) map to the clean ``Demo (synthetic data)`` label; when the model
      carries no display name the neutral ``_FALLBACK_TENANT_NAME`` is
      returned, never ``None``.
    * ``tenant_id`` — the raw tenant id as secondary context, but the
      all-zero placeholder GUID is suppressed (``None``) so the hero never
      shows it.
    * ``assessment_identity`` — the generator ``tool_display_name``, ``tool``,
      and ``version`` straight from the model.
    * ``scanned_at`` — the scan timestamp verbatim from the model.
    * ``realized_percent`` / ``realized_sentence`` — :func:`build_posture`
      output, so the opening count-up and implication derive from the exact same
      values as section A. No literal number is produced here.

    Deterministic: identical ``ScanResult`` in, identical dict out.
    """
    posture = build_posture(result)
    raw_name = result.tenant_display_name
    if raw_name in _LEGACY_DEMO_TENANT_NAMES:
        tenant_name = _DEMO_TENANT_NAME
    else:
        tenant_name = raw_name or _FALLBACK_TENANT_NAME
    tenant_id = result.tenant_id if result.tenant_id != _ZERO_TENANT_ID else None
    return {
        "tenant_name": tenant_name,
        "tenant_id": tenant_id,
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
    expected_by_check_id: dict[str, str],
) -> dict[str, object]:
    """Map one finding to its six D-section belief-block slots.

    Slot bindings (in fallback order):

    * ``expected`` — the catalog ``expected_state`` for ``finding.check_id``,
      looked up in ``expected_by_check_id``; ``"Not reported"`` when the check
      id is absent from the mapping. A pure lookup, never a derived conclusion.
    * ``summary_line`` — ``finding.customer_summary`` (may be an empty string;
      the renderer omits the line entirely when empty).
    * ``observed`` — ``finding.summary`` plus ``finding.evidence`` (a dict).
    * ``why_it_matters`` — the finding's own check-specific ``why_it_matters``
      sentence when the check author wrote one; otherwise the matching
      capability's ``why_it_matters``, plus the ``severity``/``value_impact``/
      ``blast_radius`` enum values.
    * ``recommended_action`` — ``finding.customer_next_step`` else
      ``finding.remediation``.
    * ``evidence`` — ``finding.data_sources``, ``finding.confidence_label``, and
      ``finding.limitations``.
    * ``admin_destination`` — ``finding.deep_link`` (``None`` when absent).
    * ``skip_reason`` — :func:`build_skip_reason`; the plain-language rationale
      for status ``skipped`` findings, empty for every other status. The
      finding-card template renders a "Why this was skipped" slot (replacing
      "Observed") only when this carries text.

    The "matching capability" is the first ``CapabilitySummary`` whose ``id``
    appears in ``finding.entitlements_used`` (the engine stores the check's owned
    ``required_capabilities`` there). When that list is empty or names no
    summary, the capability-dependent slot falls back to an empty string.
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
        "expected": expected_by_check_id.get(finding.check_id, "Not reported"),
        "summary_line": finding.customer_summary,
        "observed": {
            "summary": finding.summary,
            "evidence": finding.evidence,
        },
        "why_it_matters": {
            "capability": finding.why_it_matters or (matched.why_it_matters if matched else ""),
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
        "skip_reason": build_skip_reason(finding),
    }


def build_skip_reason(finding: Finding) -> str:
    """Build the "why this was skipped" rationale for a skipped finding.

    Bound strictly to model text the skip-producing paths already author —
    never invented here:

    * ``finding.summary`` — every skipped-finding producer
      (:func:`licenselens.engine.runner_findings.skipped_finding`, the
      email-proxy skip in ``runner_evaluate``, and the manual /
      environment-specific evaluators) authors the skip rationale as its
      summary ("not implemented yet", "requires manual verification", "out
      of scope", …).
    * ``finding.limitations`` — the fallback when the summary is empty.

    Any non-skipped finding returns the empty string (the finding-card
    template renders the skip slot only for status ``skipped``).
    """
    if finding.status != FindingStatus.SKIPPED:
        return ""
    if finding.summary:
        return finding.summary
    return "; ".join(limit.rstrip(".") for limit in finding.limitations if limit)


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
        "friendly_skus": [friendly_sku_name(name) for name in summary.matched_skus],
        "friendly_plans": [friendly_plan_name(name) for name in summary.matched_service_plans],
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


def build_sections(
    result: ScanResult,
    expected_by_check_id: dict[str, str] | None = None,
) -> dict[str, object]:
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

    ``expected_by_check_id`` threads the catalog ``check_id -> expected_state``
    mapping into the D-section blocks; when omitted it is resolved once here via
    :func:`licenselens.catalog.expected_states.expected_state_map` (never per
    finding).
    """
    if expected_by_check_id is None:
        expected_by_check_id = expected_state_map()
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
        "D": [
            build_belief_block(finding, result.capability_summaries, expected_by_check_id)
            for finding in findings
        ],
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


def build_sku_strip(result: ScanResult) -> list[dict[str, object]]:
    """Build the B-section owned-SKU strip payload with friendly display names.

    One entry per subscribed SKU. Each entry keeps the raw ``part_number``
    (tooltip/technical surfaces) alongside its ``friendly_name``, the license
    counts, and one ``{"name", "friendly_name"}`` dict per service plan. The
    raw names stay available for technical drill-downs; the primary rendered
    text must be the friendly name.
    """
    return [
        {
            "part_number": sku.sku_part_number,
            "friendly_name": friendly_sku_name(sku.sku_part_number),
            "capability_status": sku.capability_status,
            "consumed_units": sku.consumed_units,
            "prepaid_units": sku.prepaid_units,
            "service_plans": [
                {
                    "name": plan.service_plan_name,
                    "friendly_name": friendly_plan_name(plan.service_plan_name),
                }
                for plan in sku.service_plans
            ],
        }
        for sku in result.subscribed_skus
    ]


#: Canonical display order for the footer evidence-mode legend. The legend is
#: derived from the modes actually present in the findings — modes absent from
#: the scan never appear, and any future mode not listed here sorts after the
#: known ones in its own byte order.
_EVIDENCE_LEGEND_ORDER: Final[tuple[str, ...]] = (
    "direct",
    "proxy",
    "direct_with_proxy_fallback",
    "manual",
    "unsupported",
)

#: Human copy for each evaluation-mode enum value (footer evidence legend).
#: Raw enum strings never reach the template — only these labels do.
_EVIDENCE_LEGEND_LABELS: Final[dict[str, str]] = {
    "direct": "Direct read",
    "proxy": "Approximated (proxy) — verify in portal",
    "manual": "Manual review",
    "unsupported": "Not evaluated (no supported API path)",
    "direct_with_proxy_fallback": "Direct read, proxy fallback",
}

#: Methodology clauses keyed by the evaluation mode that triggers them. The
#: footer sentence is assembled only from the modes present in the findings,
#: so a report with no proxy checks never claims a proxy path.
_METHODOLOGY_CLAUSES: Final[dict[str, str]] = {
    "direct": "Graph and PowerShell read configuration directly where available",
    "proxy": "Secure Score approximates where direct evidence is unavailable",
    "manual": "manual review covers settings no API exposes",
    "unsupported": "remaining checks are marked unsupported in the reference",
}

#: Collection statuses that mean a collector's data is incomplete (sampled,
#: truncated, or failed) rather than fully enumerated. A collector that
#: recorded warnings or errors is also treated as incomplete.
_INCOMPLETE_COLLECTION_STATUSES: Final[frozenset[str]] = frozenset({"partial", "failed"})

#: Identity label for a scan that carries no tenant display name and ran in
#: dry-run mode (synthetic fixture data).
_SYNTHETIC_DEMO_LABEL: Final[str] = "demo (synthetic)"


def _humanize_enum(value: str) -> str:
    """Humanize an unknown enum value so the template never leaks raw tokens."""
    return " ".join(part.capitalize() for part in value.split("_"))


def _methodology_sentence(modes: set[str]) -> str:
    """Assemble the methodology note from the clauses of the modes present.

    ``direct_with_proxy_fallback`` contributes both the direct and the proxy
    clause, matching the dual evidence path that mode describes.
    """
    clauses: list[str] = []
    if "direct" in modes or "direct_with_proxy_fallback" in modes:
        clauses.append(_METHODOLOGY_CLAUSES["direct"])
    if "proxy" in modes or "direct_with_proxy_fallback" in modes:
        clauses.append(_METHODOLOGY_CLAUSES["proxy"])
    if "manual" in modes:
        clauses.append(_METHODOLOGY_CLAUSES["manual"])
    if "unsupported" in modes:
        clauses.append(_METHODOLOGY_CLAUSES["unsupported"])
    if not clauses:
        return "No findings were evaluated in this scan."
    return "; ".join(clauses) + "."


def _sampling_disclosure(result: ScanResult) -> tuple[bool, str]:
    """Return ``(sampled, text)`` for the sampled-vs-enumerated disclosure.

    ``sampled`` is True when any collection summary is partial/failed or
    carries warnings/errors; the text states which case applies. A scan with
    no collection summaries discloses that nothing was recorded rather than
    claiming full enumeration.
    """
    summaries = result.collection_summaries
    if not summaries:
        return False, "No sampling or truncation recorded for this scan."
    incomplete = [
        summary
        for summary in summaries
        if summary.status.value in _INCOMPLETE_COLLECTION_STATUSES
        or summary.warnings
        or summary.errors
    ]
    if not incomplete:
        return (
            False,
            "All inventories enumerated in full — no sampling or truncation"
            " recorded for this scan.",
        )
    return (
        True,
        f"Some inventories were sampled or truncated ({len(incomplete)} of"
        f" {len(summaries)} collectors returned partial data) — verify the"
        " affected findings in the portal.",
    )


def _assessment_identity(result: ScanResult) -> dict[str, str]:
    """Return the footer assessment identity plus the generated timestamp.

    The tenant display name wins when present; a nameless dry-run scan is
    labeled ``demo (synthetic)``; anything else falls back to the neutral
    tenant label. The timestamp flows verbatim from the model (never a
    wall-clock read here).
    """
    if result.tenant_display_name:
        name = result.tenant_display_name
    elif result.scan_mode == "dry_run":
        name = _SYNTHETIC_DEMO_LABEL
    else:
        name = _FALLBACK_TENANT_NAME
    return {
        "name": name,
        "scanned_at": result.scanned_at,
        "display_scanned_at": result.display_scanned_at,
    }


def build_provenance(result: ScanResult) -> dict[str, object]:
    """Build the footer provenance payload.

    Returns ``{"mode_legend": list[dict], "methodology": str,
    "sampling": dict, "identity": dict}``:

    * ``mode_legend`` — one ``{"mode", "label"}`` entry per evaluation mode
      actually present in the findings, ordered canonically (see
      ``_EVIDENCE_LEGEND_ORDER``) and never a fixed list. Labels are human
      copy; raw enum values stay out of the template.
    * ``methodology`` — the evidence-path note assembled from the clauses of
      the modes present (direct, proxy, manual, unsupported).
    * ``sampling`` — ``{"sampled": bool, "text": str}`` from
      :func:`_sampling_disclosure`.
    * ``identity`` — ``{"name", "scanned_at", "display_scanned_at"}`` from
      :func:`_assessment_identity`.

    Deterministic: identical ``ScanResult`` in, identical dict out.
    """
    modes = {finding.evaluation_mode.value for finding in result.findings}
    ordered_modes = [mode for mode in _EVIDENCE_LEGEND_ORDER if mode in modes]
    ordered_modes.extend(mode for mode in sorted(modes - set(_EVIDENCE_LEGEND_ORDER)))
    sampled, sampling_text = _sampling_disclosure(result)
    return {
        "mode_legend": [
            {
                "mode": mode,
                "label": _EVIDENCE_LEGEND_LABELS.get(mode, _humanize_enum(mode)),
            }
            for mode in ordered_modes
        ],
        "methodology": _methodology_sentence(modes),
        "sampling": {"sampled": sampled, "text": sampling_text},
        "identity": _assessment_identity(result),
    }

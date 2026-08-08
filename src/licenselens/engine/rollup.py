"""Capability rollup: map in-scope checks to owned capabilities for the top card.

Rules (sealed):
- `you_own` counts owned capabilities that have at least one related check in
  the packs being scanned.
- A capability is `needs_attention` if any related check is a gap.
- Otherwise `partly_set_up` if any related check is partial/error/skipped
  (proxy-capped checks are already partial via the quality policy).
- Otherwise `fully_working` if all related checks are ok.
- `not_licensed` capabilities are excluded from `you_own` (informational only).
- `% realized` = fully_working / you_own.
"""

from __future__ import annotations

from licenselens.models import (
    CAPABILITY_STATUS_LABELS,
    CapabilityOutcome,
    CapabilityRollup,
    CapabilitySummary,
    CheckDefinition,
    CheckPack,
    Finding,
    FindingStatus,
)


def _pack_values(packs: list[CheckPack] | list[str]) -> set[str]:
    return {p.value if isinstance(p, CheckPack) else str(p) for p in packs}


def _capability_status(statuses: list[FindingStatus]) -> str | None:
    if not statuses:
        return None
    if any(s == FindingStatus.GAP for s in statuses):
        return "needs_attention"
    if any(
        s in {FindingStatus.PARTIAL, FindingStatus.ERROR, FindingStatus.SKIPPED} for s in statuses
    ):
        return "partly_set_up"
    if all(s == FindingStatus.OK for s in statuses):
        return "fully_working"
    return None


def capability_rollup(
    checks: list[CheckDefinition],
    findings: list[Finding],
    owned_capabilities: list[str],
    capability_summaries: list[CapabilitySummary],
    packs_scanned: list[CheckPack] | list[str] | None,
) -> tuple[CapabilityRollup, list[CapabilityOutcome]]:
    """Return (rollup, per-capability outcomes) for the top card."""
    pack_ids = _pack_values(packs_scanned or [])
    owned = set(owned_capabilities)
    findings_by_check: dict[str, list[Finding]] = {}
    for f in findings:
        findings_by_check.setdefault(f.check_id, []).append(f)

    # Map ALL owned capabilities -> related check ids + statuses (for outcome
    # dots). The rollup counts are gated by pack below so the hero card stays
    # accurate for the packs being scanned.
    all_related: dict[str, list[str]] = {}
    in_scope_related: dict[str, list[str]] = {}
    for check in checks:
        for cap_id in check.required_capabilities:
            if cap_id in owned:
                all_related.setdefault(cap_id, []).append(check.id)
                if check.pack.value in pack_ids:
                    in_scope_related.setdefault(cap_id, []).append(check.id)

    summary_by_id = {c.id: c for c in capability_summaries}

    rollup = CapabilityRollup()
    outcomes: list[CapabilityOutcome] = []

    # not_licensed: owned-adjacent capabilities referenced by in-scope checks
    # that the tenant does not own.
    referenced = {
        cap_id
        for check in checks
        if check.pack.value in pack_ids
        for cap_id in check.required_capabilities
    }
    rollup.not_licensed = len(referenced - owned)

    for cap_id in sorted(in_scope_related):
        check_ids = in_scope_related[cap_id]
        statuses: list[FindingStatus] = []
        for check_id in check_ids:
            statuses.extend(f.status for f in findings_by_check.get(check_id, []))
        if not statuses:
            continue
        status = _capability_status(statuses)
        if status is None or status == "not_licensed":
            continue
        rollup.you_own += 1
        if status == "fully_working":
            rollup.fully_working += 1
        elif status == "needs_attention":
            rollup.needs_attention += 1
        else:
            rollup.partly_set_up += 1

        summary = summary_by_id.get(cap_id)
        outcomes.append(
            CapabilityOutcome(
                id=cap_id,
                name=summary.name if summary else cap_id,
                plain_name=summary.plain_name if summary else cap_id,
                status=status,
                status_label=CAPABILITY_STATUS_LABELS.get(status, status),
                related_check_ids=check_ids,
            )
        )

    # Add outcomes for owned capabilities that land outside the scanned packs.
    handled = {o.id for o in outcomes}
    for cap_id in sorted(all_related):
        if cap_id in handled:
            continue
        check_ids = all_related[cap_id]
        statuses: list[FindingStatus] = []
        for check_id in check_ids:
            statuses.extend(f.status for f in findings_by_check.get(check_id, []))
        if not statuses:
            continue
        status = _capability_status(statuses)
        if status is None:
            continue
        summary = summary_by_id.get(cap_id)
        outcomes.append(
            CapabilityOutcome(
                id=cap_id,
                name=summary.name if summary else cap_id,
                plain_name=summary.plain_name if summary else cap_id,
                status=status,
                status_label=CAPABILITY_STATUS_LABELS.get(status, status),
                related_check_ids=check_ids,
            )
        )
        handled.add(cap_id)

    rollup.realized_percent = (
        round(rollup.fully_working / rollup.you_own * 100) if rollup.you_own else 0
    )
    outcomes.sort(
        key=lambda o: (
            {"needs_attention": 0, "partly_set_up": 1, "fully_working": 2}.get(o.status, 9),
            o.plain_name.lower(),
        )
    )
    return rollup, outcomes

"""Deterministic move ranking for the top card.

Score is a published, deterministic heuristic:
    score = impact_weight * (1 + exposure_boost) * confidence_weight
            * proxy_factor / effort_penalty

Ties break by pack preference (identity > email > endpoint > starter) then a
stable `check_id` sort so identical scans always produce identical cards.
"""

from __future__ import annotations

from licenselens.models import (
    PROXY_CHECK_IDS,
    CheckPack,
    Confidence,
    Effort,
    ExposureClass,
    Finding,
    FindingStatus,
    TopMove,
    ValueImpact,
)

PACK_PREFERENCE: list[CheckPack] = [
    CheckPack.IDENTITY,
    CheckPack.EMAIL,
    CheckPack.ENDPOINT,
    CheckPack.STARTER,
]
PACK_RANK: dict[CheckPack, int] = {p: i for i, p in enumerate(PACK_PREFERENCE)}

IMPACT_WEIGHT: dict[ValueImpact, float] = {
    ValueImpact.HIGH: 3.0,
    ValueImpact.MEDIUM: 2.0,
    ValueImpact.LOW: 1.0,
}
EXPOSURE_BOOST: dict[ExposureClass, float] = {
    ExposureClass.EXPOSED: 3.0,
    ExposureClass.ELEVATED: 1.5,
    ExposureClass.NONE: 0.0,
}
CONFIDENCE_WEIGHT: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.85,
    Confidence.LOW: 0.6,
}
EFFORT_PENALTY: dict[Effort, float] = {
    Effort.MINUTES: 1.0,
    Effort.HOURS: 1.4,
    Effort.HALF_DAY: 1.9,
    Effort.DAYS: 2.8,
}
# Direct evidence is worth more than Secure Score proxy signals.
PROXY_FACTOR = 0.5

_MAX_TITLE_LEN = 72


def _is_proxy(finding: Finding) -> bool:
    return (
        finding.check_id in PROXY_CHECK_IDS
        or bool((finding.evidence or {}).get("proxy"))
        or any("secureScore" in s for s in finding.data_sources)
    )


def move_score(finding: Finding) -> float:
    base = IMPACT_WEIGHT.get(finding.impact, 2.0) * (
        1.0 + EXPOSURE_BOOST.get(finding.exposure_class, 0.0)
    )
    base *= CONFIDENCE_WEIGHT.get(finding.confidence, 0.85)
    base *= PROXY_FACTOR if _is_proxy(finding) else 1.0
    base /= EFFORT_PENALTY.get(finding.effort, 0.75)
    return base


def _verb_title(finding: Finding) -> str:
    text = (
        finding.customer_next_step or finding.remediation or finding.customer_title or finding.title
    ).strip()
    first = text.split(".")[0].strip()
    if len(first) > _MAX_TITLE_LEN:
        first = first[:_MAX_TITLE_LEN].rstrip().rstrip(",;: ") + "…"
    return first


def rank_moves(
    findings: list[Finding],
    *,
    limit: int = 3,
    packs: list[CheckPack] | list[str] | None = None,
) -> list[TopMove]:
    """Rank actionable findings into top-card moves.

    Only gap/partial findings are actionable. When `packs` is given, findings
    outside those packs are excluded (starter is demoted off the default card).
    """
    wanted = (
        {p.value if isinstance(p, CheckPack) else str(p) for p in packs}
        if packs is not None
        else None
    )
    actionable = [
        f
        for f in findings
        if f.status in {FindingStatus.GAP, FindingStatus.PARTIAL}
        and (wanted is None or f.pack.value in wanted)
    ]
    actionable.sort(
        key=lambda f: (
            -move_score(f),
            PACK_RANK.get(f.pack, len(PACK_PREFERENCE)),
            f.check_id,
        )
    )
    moves: list[TopMove] = []
    for f in actionable[:limit]:
        moves.append(
            TopMove(
                title=_verb_title(f),
                why=f.customer_summary or f.summary,
                effort=f.effort,
                check_ids=[f.check_id],
                deep_link=f.deep_link,
                customer_next_step=f.customer_next_step,
            )
        )
    return moves


def recommended_next_steps_from_moves(moves: list[TopMove], *, limit: int = 5) -> list[str]:
    """Back-compat list of strings, filled from structured moves."""
    steps: list[str] = []
    for move in moves:
        text = (move.customer_next_step or move.title).strip()
        if not text or text in steps:
            continue
        steps.append(text)
        if len(steps) >= limit:
            break
    return steps

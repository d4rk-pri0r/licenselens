"""Advisory vs outcome-blocking limitation policy (fail-closed required evidence).

Limitations attached to findings are either:
- advisory: informational notes that do not block a complete OK outcome
- outcome_blocking: incomplete/unsupported/unavailable REQUIRED evidence; must
  never yield FindingStatus.OK or Confidence.HIGH

Evaluators should prefer setting ``evidence["required_surface_incomplete"]=True``
when a required surface is missing; the string table below is the safety net for
existing limitation text.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from licenselens.models import Confidence, FindingStatus


class LimitationEffect(StrEnum):
    ADVISORY = "advisory"
    OUTCOME_BLOCKING = "outcome_blocking"


# Exact limitation strings known to be advisory (OK still allowed when present).
ADVISORY_LIMITATIONS: Final[frozenset[str]] = frozenset(
    {
        "AI agent risk controls vary by cloud and license; treat this as advisory.",
    }
)

# Substrings that mark a limitation as outcome-blocking (case-insensitive).
# Unsupported/unavailable REQUIRED surfaces cannot yield ok or high confidence.
OUTCOME_BLOCKING_SUBSTRINGS: Final[tuple[str, ...]] = (
    "were not readable",
    "could not be read",
    "could not confirm",
    "not readable",
    "not automatically readable",
    "unavailable",
    "unsupported",
    "required surface",
    "required evidence",
    "incomplete evidence",
    "was truncated",
    "were truncated",
    "sampling was truncated",
    "inventory was truncated",
    "only legacy",
    "proxy",
    "secure score",
    "manual verification required",
    "not exposed as a complete",
    "environment-specific",
    "portal-configured",
)


def limitation_effect(text: str) -> LimitationEffect:
    """Classify a single limitation string."""
    normalized = " ".join(text.split())
    if normalized in ADVISORY_LIMITATIONS:
        return LimitationEffect.ADVISORY
    lowered = normalized.lower()
    for marker in OUTCOME_BLOCKING_SUBSTRINGS:
        if marker in lowered:
            return LimitationEffect.OUTCOME_BLOCKING
    return LimitationEffect.ADVISORY


def has_outcome_blocking_limitations(limitations: list[str] | tuple[str, ...] | None) -> bool:
    items = limitations or []
    return any(limitation_effect(item) is LimitationEffect.OUTCOME_BLOCKING for item in items)


def apply_required_evidence_policy(
    *,
    status: FindingStatus,
    confidence: Confidence,
    limitations: list[str] | tuple[str, ...] | None,
    required_surface_incomplete: bool = False,
) -> tuple[FindingStatus, Confidence]:
    """Fail closed when required evidence is incomplete.

    Returns possibly demoted (status, confidence). Never promotes outcomes.
    """
    blocking = required_surface_incomplete or has_outcome_blocking_limitations(limitations)
    if not blocking:
        return status, confidence

    next_status = status
    next_confidence = confidence

    if next_status is FindingStatus.OK:
        next_status = FindingStatus.PARTIAL
    if next_confidence is Confidence.HIGH:
        next_confidence = Confidence.MEDIUM
    return next_status, next_confidence

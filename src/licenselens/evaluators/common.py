"""Shared evaluator contracts and helpers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from licenselens.models import CheckDefinition, Confidence, ExposureClass, FindingStatus


@dataclass
class Evaluation:
    status: FindingStatus
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    customer_summary: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    data_sources: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    exposure_class: ExposureClass = ExposureClass.NONE


Evaluator = Callable[[CheckDefinition, dict[str, Any]], Evaluation]


def score_status(ratio: float | None, *, matched: int) -> FindingStatus:
    if matched <= 0 or ratio is None:
        return FindingStatus.PARTIAL
    if ratio >= 0.85:
        return FindingStatus.OK
    if ratio >= 0.45:
        return FindingStatus.PARTIAL
    return FindingStatus.GAP

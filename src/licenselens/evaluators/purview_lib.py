"""Shared helpers for Purview governance evaluators."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from licenselens.collectors.exchange_models import PolicyItem, SurfaceStatus
from licenselens.collectors.power_data_models import PURVIEW_ADAPTER
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import exchange_bundle
from licenselens.evaluators.power_lib import power_bundle
from licenselens.models import Confidence, FindingStatus

_PURVIEW_SOURCE: Final = "Microsoft Purview / Security & Compliance PowerShell (powershell.bridge)"
_SCC_ADAPTER: Final = "scc_compliance"


class SurfaceRead(StrEnum):
    READABLE = "readable"
    ABSENT = "absent"
    DENIED = "denied"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class PurviewRead:
    state: SurfaceRead
    items: tuple[PolicyItem, ...] = ()
    adapter: str = ""
    reason: str = ""


def _classify(status: SurfaceStatus | None, raw_count: int) -> SurfaceRead:
    if status is SurfaceStatus.OK:
        return SurfaceRead.ABSENT if raw_count == 0 else SurfaceRead.READABLE
    if status is SurfaceStatus.DENIED:
        return SurfaceRead.DENIED
    return SurfaceRead.UNREADABLE


def read_surface(evidence: Mapping[str, Any], name: str) -> PurviewRead:
    """Read a Purview surface from power-data (purview_governance) then SCC."""
    power = power_bundle(evidence)
    if power is not None:
        payload = power.adapters.get(PURVIEW_ADAPTER)
        if payload is not None and name in payload.surfaces:
            surface = payload.surfaces[name]
            return PurviewRead(
                _classify(surface.status, surface.raw_count),
                tuple(surface.items),
                PURVIEW_ADAPTER,
                surface.reason,
            )
    exo = exchange_bundle(evidence)
    if exo is not None:
        payload = exo.adapters.get(_SCC_ADAPTER)
        if payload is not None and name in payload.surfaces:
            surface = payload.surfaces[name]
            return PurviewRead(
                _classify(surface.status, surface.raw_count),
                tuple(surface.items),
                _SCC_ADAPTER,
                surface.reason,
            )
    return PurviewRead(SurfaceRead.UNREADABLE)


def direct_meta() -> dict[str, Any]:
    return {
        "confidence": Confidence.HIGH,
        "data_sources": [_PURVIEW_SOURCE],
        "limitations": [],
    }


def unreadable(surface: str, customer: str) -> Evaluation:
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=f"{surface} could not be read; treated as unresolved.",
        evidence={"surface": surface, "readable": False},
        customer_summary=customer,
        confidence=Confidence.MEDIUM,
        limitations=[f"Purview {surface} was not readable via Security & Compliance PowerShell."],
    )


def denied(surface: str, customer: str) -> Evaluation:
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=f"Access to {surface} was denied; configuration could not be confirmed.",
        evidence={"surface": surface, "denied": True, "readable": False},
        customer_summary=customer,
        confidence=Confidence.MEDIUM,
        limitations=[f"Permission denied reading Purview {surface}."],
    )

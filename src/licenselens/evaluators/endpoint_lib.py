"""Shared helpers for Intune/MDE/XDR endpoint evaluators."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.models import Confidence, FindingStatus

INTUNE_SOURCE: Final = "graph.deviceManagement"

_DIRECT_META: Final = {
    "confidence": Confidence.HIGH,
    "data_sources": [INTUNE_SOURCE],
    "limitations": [],
}


def intune_bundle(evidence: Mapping[str, Any]) -> dict[str, Any] | None:
    raw = evidence.get("intune_bundle")
    return raw if isinstance(raw, dict) else None


def surface_error(bundle: dict[str, Any] | None, name: str) -> str:
    if bundle is None:
        return "Intune evidence was not collected."
    return str((bundle.get("errors") or {}).get(name) or "")


def compliance_policies(bundle: dict[str, Any] | None) -> list[dict[str, Any]]:
    if bundle is None:
        return []
    return [p for p in bundle.get("compliance_policies") or [] if isinstance(p, dict)]


def configuration_policies(bundle: dict[str, Any] | None) -> list[dict[str, Any]]:
    if bundle is None:
        return []
    return [p for p in bundle.get("configuration_policies") or [] if isinstance(p, dict)]


def managed_devices(bundle: dict[str, Any] | None) -> list[dict[str, Any]]:
    if bundle is None:
        return []
    return [d for d in bundle.get("managed_devices") or [] if isinstance(d, dict)]


def atp_state(bundle: dict[str, Any] | None) -> dict[str, Any] | None:
    if bundle is None:
        return None
    raw = bundle.get("atp_onboarding_state")
    return raw if isinstance(raw, dict) else None


def direct_meta() -> dict[str, Any]:
    return dict(_DIRECT_META)


def unavailable(
    summary: str,
    *,
    surface: str,
    customer_summary: str,
    evidence: dict[str, Any] | None = None,
) -> Evaluation:
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=summary,
        evidence={**(evidence or {}), "surface": surface, "readable": False},
        customer_summary=customer_summary,
        confidence=Confidence.MEDIUM,
        data_sources=[INTUNE_SOURCE],
        limitations=[f"{surface} was not readable; verify in the Microsoft Intune admin center."],
    )

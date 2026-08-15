"""Shared helpers for SharePoint/OneDrive and Teams collaboration evaluators."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from licenselens.collectors.collaboration_models import (
    CollaborationBundle,
    CollaborationSurface,
    PolicyItem,
    SurfaceStatus,
)
from licenselens.collectors.exchange_models import PolicyKind
from licenselens.evaluators.common import Evaluation
from licenselens.models import Confidence, FindingStatus

_COLLAB_SOURCE: Final = "Microsoft Teams / SharePoint Online PowerShell (powershell.bridge)"

_DIRECT_META: Final = {
    "confidence": Confidence.HIGH,
    "data_sources": [_COLLAB_SOURCE],
    "limitations": [],
}

_UNAVAILABLE_META: Final = {
    "confidence": Confidence.MEDIUM,
    "limitations": ["Collaboration surface was not readable; verify in the admin portal."],
}


def collaboration_bundle(evidence: Mapping[str, Any]) -> CollaborationBundle | None:
    raw = evidence.get("collaboration_bundle")
    if not isinstance(raw, dict):
        return None
    try:
        return CollaborationBundle.model_validate(raw)
    except Exception:
        return None


def surface(
    bundle: CollaborationBundle | None,
    adapter: str,
    name: str,
) -> CollaborationSurface | None:
    if bundle is None:
        return None
    payload = bundle.adapters.get(adapter)
    if payload is None:
        return None
    return payload.surfaces.get(name)


def usable(bundle: CollaborationBundle | None, adapter: str, name: str) -> bool:
    found = surface(bundle, adapter, name)
    return found is not None and found.status is SurfaceStatus.OK


def items(bundle: CollaborationBundle | None, adapter: str, name: str) -> list[PolicyItem]:
    found = surface(bundle, adapter, name)
    if found is None or found.status is not SurfaceStatus.OK:
        return []
    return list(found.items)


def prop(item: PolicyItem, name: str) -> Any:
    return item.properties.get(name)


def prop_bool(item: PolicyItem, name: str, default: bool = False) -> bool:
    value = prop(item, name)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "enabled", "on", "yes", "1"}:
            return True
        if lowered in {"false", "disabled", "off", "no", "0"}:
            return False
    return default


def prop_str(item: PolicyItem, name: str, default: str = "") -> str:
    value = prop(item, name)
    return value if isinstance(value, str) else default


def prop_int(item: PolicyItem, name: str) -> int | None:
    value = prop(item, name)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def direct_meta() -> dict[str, Any]:
    return dict(_DIRECT_META)


def unavailable(
    summary: str,
    *,
    adapter: str,
    surface_name: str,
    customer_summary: str,
) -> Evaluation:
    return Evaluation(
        status=FindingStatus.PARTIAL,
        summary=summary,
        evidence={"adapter": adapter, "surface": surface_name, "readable": False},
        customer_summary=customer_summary,
        **_UNAVAILABLE_META,
    )


def not_applicable(summary: str, *, note: str, evidence: dict[str, Any]) -> Evaluation:
    return Evaluation(
        status=FindingStatus.SKIPPED,
        summary=summary,
        evidence=evidence,
        customer_summary=note,
        confidence=Confidence.MEDIUM,
        limitations=[note],
    )


def custom_items(bundle: CollaborationBundle | None, adapter: str, name: str) -> list[PolicyItem]:
    return [item for item in items(bundle, adapter, name) if item.kind is PolicyKind.CUSTOM]


_SPO_ADAPTER: Final = "spo_tenant"


def spo_sharing_capability(bundle: CollaborationBundle | None) -> str | None:
    """Return the tenant SharePoint sharing capability value (lowercased), if readable."""
    if not usable(bundle, _SPO_ADAPTER, "sharing_capability"):
        return None
    for item in items(bundle, _SPO_ADAPTER, "sharing_capability"):
        value = prop_str(item, "SharingCapability")
        if value:
            return value.strip().lower()
    return None

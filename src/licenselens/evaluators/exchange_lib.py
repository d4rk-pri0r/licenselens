"""Shared helpers for Exchange Online and Security Suite evaluators."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Final

from licenselens.collectors.exchange_models import (
    ExchangeBundle,
    ExchangeSurface,
    PolicyItem,
    SurfaceStatus,
)
from licenselens.models import Confidence

Predicate = Callable[[PolicyItem], bool]

_EXCHANGE_SOURCE: Final = "Exchange Online PowerShell (powershell.bridge)"
_SCC_SOURCE: Final = "Security & Compliance PowerShell (scc_compliance)"

_DIRECT_META: Final = {
    "confidence": Confidence.HIGH,
    "data_sources": [_EXCHANGE_SOURCE, _SCC_SOURCE],
}


def exchange_bundle(evidence: Mapping[str, Any]) -> ExchangeBundle | None:
    raw = evidence.get("exchange_bundle")
    if not isinstance(raw, dict):
        return None
    try:
        return ExchangeBundle.model_validate(raw)
    except Exception:
        return None


def surface(bundle: ExchangeBundle | None, adapter: str, name: str) -> ExchangeSurface | None:
    if bundle is None:
        return None
    payload = bundle.adapters.get(adapter)
    if payload is None:
        return None
    return payload.surfaces.get(name)


def usable(bundle: ExchangeBundle | None, adapter: str, name: str) -> bool:
    found = surface(bundle, adapter, name)
    return found is not None and found.status is SurfaceStatus.OK


def items(bundle: ExchangeBundle | None, adapter: str, name: str) -> list[PolicyItem]:
    found = surface(bundle, adapter, name)
    if found is None or found.status is not SurfaceStatus.OK:
        return []
    return list(found.items)


def enabled_items(bundle: ExchangeBundle | None, adapter: str, name: str) -> list[PolicyItem]:
    return [item for item in items(bundle, adapter, name) if item.enabled is not False]


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


def direct_meta(*, data_sources: tuple[str, ...] = ()) -> dict[str, Any]:
    sources = list(_DIRECT_META["data_sources"])
    sources.extend(src for src in data_sources if src not in sources)
    return {"confidence": Confidence.HIGH, "data_sources": sources, "limitations": []}


def any_enabled_with(
    bundle: ExchangeBundle | None,
    adapter: str,
    surface_name: str,
    predicate: Predicate,
) -> bool | None:
    """Return whether any enabled item matches; ``None`` when surface unreadable."""
    if not usable(bundle, adapter, surface_name):
        return None
    return any(predicate(item) for item in enabled_items(bundle, adapter, surface_name))


def every_enabled_with(
    bundle: ExchangeBundle | None,
    adapter: str,
    surface_name: str,
    predicate: Predicate,
) -> bool | None:
    """Return whether every enabled item matches; ``None`` when surface unreadable."""
    if not usable(bundle, adapter, surface_name):
        return None
    selected = enabled_items(bundle, adapter, surface_name)
    if not selected:
        return None
    return all(predicate(item) for item in selected)

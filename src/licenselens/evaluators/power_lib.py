"""Shared helpers for Power Platform and Power BI evaluators."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from licenselens.collectors.power_data_models import (
    PBI_TENANT_ADAPTER,
    PP_TENANT_ADAPTER,
    PolicyItem,
    PowerDataBundle,
    PowerDataSurface,
    SurfaceStatus,
)
from licenselens.evaluators.common import Evaluation
from licenselens.models import Confidence, FindingStatus

_POWER_SOURCE: Final = "Power Platform / Power BI PowerShell (powershell.bridge)"

_DIRECT_META: Final = {
    "confidence": Confidence.HIGH,
    "data_sources": [_POWER_SOURCE],
    "limitations": [],
}

_UNAVAILABLE_META: Final = {
    "confidence": Confidence.MEDIUM,
    "limitations": [
        "Power Platform / Power BI surface was not readable; verify in the admin portal."
    ],
}


def power_bundle(evidence: Mapping[str, Any]) -> PowerDataBundle | None:
    raw = evidence.get("power_data_bundle")
    if not isinstance(raw, dict):
        return None
    try:
        return PowerDataBundle.model_validate(raw)
    except Exception:
        return None


def surface(
    bundle: PowerDataBundle | None,
    adapter: str,
    name: str,
) -> PowerDataSurface | None:
    if bundle is None:
        return None
    payload = bundle.adapters.get(adapter)
    if payload is None:
        return None
    return payload.surfaces.get(name)


def usable(bundle: PowerDataBundle | None, adapter: str, name: str) -> bool:
    found = surface(bundle, adapter, name)
    return found is not None and found.status is SurfaceStatus.OK


def items(bundle: PowerDataBundle | None, adapter: str, name: str) -> list[PolicyItem]:
    found = surface(bundle, adapter, name)
    if found is None or found.status is not SurfaceStatus.OK:
        return []
    return list(found.items)


def prop(item: PolicyItem, name: str) -> Any:
    return item.properties.get(name)


def prop_bool_optional(item: PolicyItem, name: str) -> bool | None:
    value = prop(item, name)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "enabled", "on", "yes", "1"}:
            return True
        if lowered in {"false", "disabled", "off", "no", "0"}:
            return False
    return None


def prop_str(item: PolicyItem, name: str, default: str = "") -> str:
    value = prop(item, name)
    return value if isinstance(value, str) else default


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


def _first_item(bundle: PowerDataBundle | None, adapter: str, name: str) -> PolicyItem | None:
    found = items(bundle, adapter, name)
    return found[0] if found else None


def tenant_bool(
    bundle: PowerDataBundle | None,
    surface_name: str,
    prop_name: str,
) -> bool | None:
    """Return the tenant-level boolean for a surface, or ``None`` when unreadable."""
    item = _first_item(bundle, PP_TENANT_ADAPTER, surface_name)
    if item is None:
        return None
    return prop_bool_optional(item, prop_name)


def tenant_bool_result(
    *,
    bundle: PowerDataBundle | None,
    surface_name: str,
    prop_name: str,
    expect: bool,
    ok_summary: str,
    gap_summary: str,
    customer_ok: str,
    customer_gap: str,
) -> Evaluation:
    """Map a tenant-level boolean to OK/GAP/PARTIAL (never a false gap)."""
    if not usable(bundle, PP_TENANT_ADAPTER, surface_name):
        return unavailable(
            f"{surface_name} could not be read; treated as unresolved.",
            adapter=PP_TENANT_ADAPTER,
            surface_name=surface_name,
            customer_summary="We could not confirm this tenant setting.",
        )
    value = tenant_bool(bundle, surface_name, prop_name)
    evidence = {"surface": surface_name, "property": prop_name, "value": value}
    if value is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"{surface_name} was returned without a conclusive value for {prop_name}.",
            evidence=evidence,
            customer_summary="Confirm this tenant setting in the admin portal.",
            confidence=Confidence.MEDIUM,
            limitations=[f"{prop_name} was not reported."],
        )
    if value is expect:
        return Evaluation(
            status=FindingStatus.OK,
            summary=ok_summary,
            evidence=evidence,
            customer_summary=customer_ok,
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=gap_summary,
        evidence=evidence,
        customer_summary=customer_gap,
        **direct_meta(),
    )


def pbi_bool(
    bundle: PowerDataBundle | None,
    surface_name: str,
) -> bool | None:
    """Return the Power BI tenant-setting boolean for a surface, if readable."""
    item = _first_item(bundle, PBI_TENANT_ADAPTER, surface_name)
    if item is None:
        return None
    value = prop_bool_optional(item, "enabled")
    if value is None:
        value = item.enabled
    return value


def pbi_bool_result(
    *,
    bundle: PowerDataBundle | None,
    surface_name: str,
    expect: bool,
    ok_summary: str,
    gap_summary: str,
    customer_ok: str,
    customer_gap: str,
) -> Evaluation:
    """Map a Power BI tenant-setting boolean to OK/GAP/PARTIAL."""
    if not usable(bundle, PBI_TENANT_ADAPTER, surface_name):
        return unavailable(
            f"{surface_name} could not be read; treated as unresolved.",
            adapter=PBI_TENANT_ADAPTER,
            surface_name=surface_name,
            customer_summary="We could not confirm this Power BI tenant setting.",
        )
    value = pbi_bool(bundle, surface_name)
    evidence = {"surface": surface_name, "enabled": value}
    if value is None:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"{surface_name} was returned without a conclusive enabled value.",
            evidence=evidence,
            customer_summary="Confirm this Power BI tenant setting in the admin portal.",
            confidence=Confidence.MEDIUM,
            limitations=[f"{surface_name} enabled state was not reported."],
        )
    if value is expect:
        return Evaluation(
            status=FindingStatus.OK,
            summary=ok_summary,
            evidence=evidence,
            customer_summary=customer_ok,
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary=gap_summary,
        evidence=evidence,
        customer_summary=customer_gap,
        **direct_meta(),
    )

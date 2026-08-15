"""Load capability catalog and map tenant SKUs to owned capabilities."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import yaml

from licenselens.catalog.capability_meta import (
    ALL_CATALOG_CLOUDS,
    CapabilityBackend,
    CatalogCloud,
    CatalogLoadError,
    EntitlementKind,
)
from licenselens.models import Capability, CapabilitySummary, ServicePlan, SubscribedSku, Workload
from licenselens.paths import catalog_dir

_ACTIVE_PLAN_STATUSES: Final[frozenset[str]] = frozenset({"success", "enabled", ""})
_INACTIVE_SKU_STATUSES: Final[frozenset[str]] = frozenset(
    {"disabled", "deleted", "suspended", "lockedout"}
)


def _service_plan_is_active(plan: ServicePlan) -> bool:
    return (plan.provisioning_status or "Success").lower() in _ACTIVE_PLAN_STATUSES


def _sku_is_active(sku: SubscribedSku) -> bool:
    status = (sku.capability_status or "Enabled").lower()
    return status not in _INACTIVE_SKU_STATUSES


def _clean(text: str | None) -> str:
    if not text:
        return ""
    return " ".join(str(text).split())


def _string_list(raw: object) -> list[str]:
    if not raw:
        return []
    if not isinstance(raw, list):
        message = f"expected list of strings, got {type(raw).__name__}"
        raise CatalogLoadError((message,))
    return [str(item) for item in raw]


def _parse_entitlement_kind(raw: object) -> str:
    value = str(raw or EntitlementKind.INCLUDED.value)
    try:
        return EntitlementKind(value).value
    except ValueError:
        raise CatalogLoadError((f"unknown_entitlement_kind:{value}",)) from None


def _parse_clouds(raw: object) -> list[str]:
    if not raw:
        return []
    clouds: list[str] = []
    for item in _string_list(raw):
        try:
            clouds.append(CatalogCloud(item).value)
        except ValueError:
            raise CatalogLoadError((f"unknown_catalog_cloud:{item}",)) from None
    return clouds


def _parse_backends(raw: object) -> list[str]:
    if not raw:
        return []
    backends: list[str] = []
    for item in _string_list(raw):
        try:
            backends.append(CapabilityBackend(item).value)
        except ValueError:
            raise CatalogLoadError((f"unknown_capability_backend:{item}",)) from None
    return backends


def _capability_from_item(item: dict[str, object]) -> Capability:
    cap_id = str(item["id"])
    workloads = [Workload(str(workload)) for workload in _string_list(item.get("workloads"))]
    return Capability(
        id=cap_id,
        name=str(item["name"]),
        description=_clean(str(item["description"]) if item.get("description") else None),
        plain_name=_clean(str(item["plain_name"]) if item.get("plain_name") else None)
        or str(item["name"]),
        outcome=_clean(str(item["outcome"]) if item.get("outcome") else None),
        why_it_matters=_clean(str(item["why_it_matters"]) if item.get("why_it_matters") else None),
        if_unused=_clean(str(item["if_unused"]) if item.get("if_unused") else None),
        workloads=workloads,
        service_plan_names=_string_list(item.get("service_plan_names")),
        sku_part_numbers=_string_list(item.get("sku_part_numbers")),
        service_plan_aliases=_string_list(item.get("service_plan_aliases")),
        sku_aliases=_string_list(item.get("sku_aliases")),
        entitlement_kind=_parse_entitlement_kind(item.get("entitlement_kind")),
        clouds=_parse_clouds(item.get("clouds")),
        backends=_parse_backends(item.get("backends")),
        source_version=str(item.get("source_version") or ""),
        docs_url=str(item["docs_url"]) if item.get("docs_url") else None,
    )


def _validate_capabilities(capabilities: list[Capability]) -> None:
    diagnostics: list[str] = []
    seen_ids: set[str] = set()
    for cap in capabilities:
        if cap.id in seen_ids:
            diagnostics.append(f"duplicate_capability_id:{cap.id}")
        seen_ids.add(cap.id)
        plan_tokens = {name.upper() for name in cap.service_plan_names}
        plan_aliases = {name.upper() for name in cap.service_plan_aliases}
        overlap = sorted(plan_tokens & plan_aliases)
        diagnostics.extend(f"redundant_plan_alias:{cap.id}:{token}" for token in overlap)
        sku_tokens = {name.upper() for name in cap.sku_part_numbers}
        sku_aliases = {name.upper() for name in cap.sku_aliases}
        sku_overlap = sorted(sku_tokens & sku_aliases)
        diagnostics.extend(f"redundant_sku_alias:{cap.id}:{token}" for token in sku_overlap)

    if diagnostics:
        raise CatalogLoadError(tuple(sorted(set(diagnostics))))


def load_capabilities(path: Path | None = None) -> list[Capability]:
    catalog_path = path or (catalog_dir() / "capabilities.yaml")
    raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    items = raw.get("capabilities") or []
    capabilities: list[Capability] = []
    for item in items:
        if not isinstance(item, dict):
            raise CatalogLoadError(("invalid_capability_entry",))
        capabilities.append(_capability_from_item(item))
    _validate_capabilities(capabilities)
    return capabilities


def _cloud_allows(cap: Capability, cloud: CatalogCloud | str | None) -> bool:
    if cloud is None:
        return True
    if not cap.clouds:
        return True
    cloud_value = cloud.value if isinstance(cloud, CatalogCloud) else str(cloud)
    return cloud_value in cap.clouds


def resolve_owned_capabilities(
    capabilities: list[Capability],
    skus: list[SubscribedSku],
    *,
    cloud: CatalogCloud | str | None = None,
) -> list[str]:
    """Return capability ids unlocked by the tenant's subscribed SKUs/plans.

    Unknown service plans and disabled plans/SKUs never unlock capabilities.
    Optional ``cloud`` filters capabilities that declare a non-empty clouds list.
    """
    active_skus = [sku for sku in skus if _sku_is_active(sku)]
    plan_names = {
        plan.service_plan_name.upper()
        for sku in active_skus
        for plan in sku.service_plans
        if _service_plan_is_active(plan) and plan.service_plan_name
    }
    part_numbers = {sku.sku_part_number.upper() for sku in active_skus if sku.sku_part_number}

    owned: list[str] = []
    for cap in capabilities:
        if not _cloud_allows(cap, cloud):
            continue
        plan_hit = bool(cap.matching_plan_names & plan_names)
        sku_hit = bool(cap.matching_sku_part_numbers & part_numbers)
        if plan_hit or sku_hit:
            owned.append(cap.id)
    return sorted(set(owned))


def capability_summaries_for(
    capabilities: list[Capability],
    owned_ids: list[str],
    skus: list[SubscribedSku],
) -> list[CapabilitySummary]:
    """Build plain-language cards for capabilities the tenant owns."""
    by_id = {cap.id: cap for cap in capabilities}
    active_skus = [sku for sku in skus if _sku_is_active(sku)]

    plan_to_sku: dict[str, str] = {}
    for sku in active_skus:
        for plan in sku.service_plans:
            if _service_plan_is_active(plan):
                plan_to_sku[plan.service_plan_name.upper()] = sku.sku_part_number

    summaries: list[CapabilitySummary] = []
    for cap_id in owned_ids:
        cap = by_id.get(cap_id)
        if cap is None:
            continue
        plan_keys = cap.matching_plan_names
        sku_keys = cap.matching_sku_part_numbers

        matched_service_plans = sorted(
            {
                plan.service_plan_name
                for sku in active_skus
                for plan in sku.service_plans
                if _service_plan_is_active(plan) and plan.service_plan_name.upper() in plan_keys
            }
        )

        matched_skus_set = {
            sku.sku_part_number for sku in active_skus if sku.sku_part_number.upper() in sku_keys
        }
        for plan_name in matched_service_plans:
            parent_sku = plan_to_sku.get(plan_name.upper())
            if parent_sku:
                matched_skus_set.add(parent_sku)

        summaries.append(
            CapabilitySummary(
                id=cap.id,
                name=cap.name,
                plain_name=cap.display_plain_name,
                matched_skus=sorted(matched_skus_set),
                matched_service_plans=matched_service_plans,
                outcome=cap.outcome,
                why_it_matters=cap.why_it_matters,
                if_unused=cap.if_unused,
                docs_url=cap.docs_url,
            )
        )
    return summaries


def catalog_cloud_values() -> tuple[str, ...]:
    """Stable list of catalog cloud identifiers for docs and tests."""
    return tuple(cloud.value for cloud in ALL_CATALOG_CLOUDS)

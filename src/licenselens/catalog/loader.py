"""Load capability catalog and map tenant SKUs to owned capabilities."""

from __future__ import annotations

from pathlib import Path

import yaml

from licenselens.models import Capability, SubscribedSku, Workload
from licenselens.paths import catalog_dir


def load_capabilities(path: Path | None = None) -> list[Capability]:
    catalog_path = path or (catalog_dir() / "capabilities.yaml")
    raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    items = raw.get("capabilities") or []
    capabilities: list[Capability] = []
    for item in items:
        workloads = [Workload(w) for w in item.get("workloads", [])]
        capabilities.append(
            Capability(
                id=item["id"],
                name=item["name"],
                description=item.get("description", ""),
                workloads=workloads,
                service_plan_names=list(item.get("service_plan_names") or []),
                sku_part_numbers=list(item.get("sku_part_numbers") or []),
                docs_url=item.get("docs_url"),
            )
        )
    return capabilities


def resolve_owned_capabilities(
    capabilities: list[Capability],
    skus: list[SubscribedSku],
) -> list[str]:
    """Return capability ids unlocked by the tenant's subscribed SKUs/plans."""
    plan_names = {
        p.service_plan_name.upper()
        for sku in skus
        for p in sku.service_plans
        if (p.provisioning_status or "Success").lower() in {"success", "enabled", ""}
    }
    part_numbers = {s.sku_part_number.upper() for s in skus if s.sku_part_number}

    owned: list[str] = []
    for cap in capabilities:
        plan_hit = any(p.upper() in plan_names for p in cap.service_plan_names)
        sku_hit = any(s.upper() in part_numbers for s in cap.sku_part_numbers)
        if plan_hit or sku_hit:
            owned.append(cap.id)
    return sorted(set(owned))

"""Load capability catalog and map tenant SKUs to owned capabilities."""

from __future__ import annotations

from pathlib import Path

import yaml

from licenselens.models import Capability, CapabilitySummary, SubscribedSku, Workload
from licenselens.paths import catalog_dir


def _clean(text: str | None) -> str:
    if not text:
        return ""
    return " ".join(str(text).split())


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
                description=_clean(item.get("description")),
                plain_name=_clean(item.get("plain_name")) or item["name"],
                outcome=_clean(item.get("outcome")),
                why_it_matters=_clean(item.get("why_it_matters")),
                if_unused=_clean(item.get("if_unused")),
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


def capability_summaries_for(
    capabilities: list[Capability],
    owned_ids: list[str],
) -> list[CapabilitySummary]:
    """Build plain-language cards for capabilities the tenant owns."""
    by_id = {c.id: c for c in capabilities}
    summaries: list[CapabilitySummary] = []
    for cap_id in owned_ids:
        cap = by_id.get(cap_id)
        if cap is None:
            continue
        summaries.append(
            CapabilitySummary(
                id=cap.id,
                name=cap.name,
                plain_name=cap.display_plain_name,
                outcome=cap.outcome,
                why_it_matters=cap.why_it_matters,
                if_unused=cap.if_unused,
                docs_url=cap.docs_url,
            )
        )
    return summaries

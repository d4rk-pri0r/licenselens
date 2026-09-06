"""Collect per-capability assigned-plan counts (no user objects)."""

from __future__ import annotations

from typing import Any

from licenselens.errors import GraphError
from licenselens.graph import GraphClient
from licenselens.models import Capability, SubscribedSku

__all__ = ["DEMO_LICENSE_ASSIGNMENT", "collect_license_assignment"]

PROTECTIVE_CAPABILITIES: tuple[str, ...] = (
    "entra_id_p2",
    "identity_protection",
    "defender_office_p2",
    "defender_endpoint_p2",
    "purview_dlp",
)

DEMO_LICENSE_ASSIGNMENT: dict[str, Any] = {
    "enabled_member_users": 100,
    "by_capability": {
        cap: {"assigned_users": 87, "method": "demo"} for cap in PROTECTIVE_CAPABILITIES
    },
}


def collect_license_assignment(
    client: GraphClient,
    *,
    capabilities: list[Capability],
    owned_ids: list[str],
    skus: list[SubscribedSku],
) -> dict[str, Any]:
    """Return assigned-user counts per owned capability. Counts only."""
    by_id = {cap.id: cap for cap in capabilities}
    enabled_members: int | None
    try:
        enabled_members = client.get_count(
            "/users/$count",
            params={"$filter": "accountEnabled eq true and userType eq 'Member'"},
        )
    except GraphError:
        enabled_members = None

    by_capability: dict[str, dict[str, Any]] = {}
    for cap_id in owned_ids:
        cap = by_id.get(cap_id)
        if cap is None or not cap.service_plan_ids:
            continue
        assigned, method = _count_for_capability(client, cap, skus)
        by_capability[cap_id] = {"assigned_users": assigned, "method": method}

    return {
        "enabled_member_users": enabled_members,
        "by_capability": by_capability,
    }


def _count_for_capability(
    client: GraphClient,
    cap: Capability,
    skus: list[SubscribedSku],
) -> tuple[int | None, str]:
    for guid in cap.service_plan_ids:
        filt = f"assignedPlans/any(p:p/servicePlanId eq {guid} and p/capabilityStatus eq 'Enabled')"
        try:
            return client.get_count("/users/$count", params={"$filter": filt}), "assignedPlans"
        except GraphError as exc:
            if getattr(exc, "status_code", None) != 400:
                continue
            break
        except Exception:
            continue

    sku_ids = [
        sku.sku_id
        for sku in skus
        if sku.sku_id and sku.sku_part_number.upper() in cap.matching_sku_part_numbers
    ]
    total = 0
    any_ok = False
    for sku_id in sku_ids:
        filt = f"assignedLicenses/any(s:s/skuId eq {sku_id})"
        try:
            total += client.get_count("/users/$count", params={"$filter": filt})
            any_ok = True
        except GraphError:
            continue
    if any_ok:
        return total, "assignedLicenses"
    return None, "unavailable"

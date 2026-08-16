"""Collect subscribed SKUs and service plans from Microsoft Graph."""

from __future__ import annotations

from licenselens.auth import AuthContext, AuthMode
from licenselens.errors import AuthError
from licenselens.graph import GraphClient
from licenselens.models import ServicePlan, SubscribedSku

# Fixture used for dry-run / demos without a tenant.
_DEMO_SKUS: list[SubscribedSku] = [
    SubscribedSku(
        sku_id="demo-e5",
        sku_part_number="SPE_E5",
        capability_status="Enabled",
        prepaid_units=100,
        consumed_units=87,
        service_plans=[
            ServicePlan(
                service_plan_id="eec0eb4f-6444-4f95-aba0-50c24d67f998",
                service_plan_name="AAD_PREMIUM_P2",
                provisioning_status="Success",
            ),
            ServicePlan(
                service_plan_id="8a256a2b-b617-496d-b51b-e76466e88db0",
                service_plan_name="MFA_PREMIUM",
                provisioning_status="Success",
            ),
            ServicePlan(
                service_plan_id="8c098270-9dd4-4350-9b30-ba4703f3b36b",
                service_plan_name="ADALLOM_S_O365",
                provisioning_status="Success",
            ),
            ServicePlan(
                service_plan_id="4de31727-a228-4ec3-a5bf-8e45b5ca48cc",
                service_plan_name="EQUIVIO_ANALYTICS",
                provisioning_status="Success",
            ),
            ServicePlan(
                service_plan_id="9f431833-0334-42de-a7dc-70aa40db46db",
                service_plan_name="LOCKBOX_ENTERPRISE",
                provisioning_status="Success",
            ),
            ServicePlan(
                service_plan_id="efb0351d-3b08-4503-993d-383af8de41e3",
                service_plan_name="MIP_S_CLP2",
                provisioning_status="Success",
            ),
            ServicePlan(
                service_plan_id="8e0c0a52-6a6c-4d40-8370-dd62790dcd70",
                service_plan_name="THREAT_INTELLIGENCE",
                provisioning_status="Success",
            ),
            ServicePlan(
                service_plan_name="DEFENDER_ENDPOINT_P2",
                provisioning_status="Success",
            ),
        ],
    ),
    SubscribedSku(
        sku_id="demo-sentinel",
        sku_part_number="MICROSOFT_SENTINEL",
        capability_status="Enabled",
        prepaid_units=1,
        consumed_units=1,
        service_plans=[
            ServicePlan(
                service_plan_name="MICROSOFT_SENTINEL",
                provisioning_status="Success",
            ),
        ],
    ),
]


def _parse_sku(raw: dict) -> SubscribedSku:
    prepaid = raw.get("prepaidUnits") or {}
    enabled_units = prepaid.get("enabled")
    plans_raw = raw.get("servicePlans") or []
    plans = [
        ServicePlan(
            service_plan_id=p.get("servicePlanId"),
            service_plan_name=str(p.get("servicePlanName") or ""),
            provisioning_status=p.get("provisioningStatus"),
        )
        for p in plans_raw
        if p.get("servicePlanName")
    ]
    return SubscribedSku(
        sku_id=raw.get("skuId"),
        sku_part_number=str(raw.get("skuPartNumber") or raw.get("skuId") or "UNKNOWN"),
        capability_status=raw.get("capabilityStatus"),
        prepaid_units=int(enabled_units) if enabled_units is not None else None,
        consumed_units=raw.get("consumedUnits"),
        service_plans=plans,
    )


def skus_from_graph_values(values: list[dict]) -> list[SubscribedSku]:
    """Parse Graph subscribedSkus value array (test helper + collector)."""
    return [_parse_sku(item) for item in values]


def collect_subscribed_skus_live(client: GraphClient) -> list[SubscribedSku]:
    """Fetch /subscribedSkus via Graph."""
    rows = client.get_list("/subscribedSkus")
    return skus_from_graph_values(rows)


def collect_subscribed_skus(
    auth: AuthContext,
    *,
    dry_run: bool = True,
    client: GraphClient | None = None,
) -> list[SubscribedSku]:
    """Return subscribed SKUs (demo data or live Graph)."""
    if dry_run or auth.mode == AuthMode.DRY_RUN:
        return list(_DEMO_SKUS)

    if client is not None:
        return collect_subscribed_skus_live(client)

    if not auth.has_credentials:
        raise AuthError("Live SKU collection requires authenticated credentials.")

    with GraphClient(auth) as graph:
        return collect_subscribed_skus_live(graph)


def demo_skus() -> list[SubscribedSku]:
    return list(_DEMO_SKUS)

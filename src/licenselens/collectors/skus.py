"""Collect subscribed SKUs and service plans from Microsoft Graph."""

from __future__ import annotations

from licenselens.auth import AuthContext, AuthMode
from licenselens.models import ServicePlan, SubscribedSku

# Fixture used for dry-run / demos until live Graph is wired.
_DEMO_SKUS: list[SubscribedSku] = [
    SubscribedSku(
        sku_id="demo-e5",
        sku_part_number="SPE_E5",
        capability_status="Enabled",
        prepaid_units=100,
        consumed_units=87,
        service_plans=[
            ServicePlan(service_plan_name="AAD_PREMIUM_P2", provisioning_status="Success"),
            ServicePlan(service_plan_name="MFA_PREMIUM", provisioning_status="Success"),
            ServicePlan(
                service_plan_name="ADALLOM_S_O365",
                provisioning_status="Success",
            ),
            ServicePlan(service_plan_name="EQUIVIO_ANALYTICS", provisioning_status="Success"),
            ServicePlan(service_plan_name="LOCKBOX_ENTERPRISE", provisioning_status="Success"),
            ServicePlan(service_plan_name="MIP_S_CLP2", provisioning_status="Success"),
            ServicePlan(service_plan_name="THREAT_INTELLIGENCE", provisioning_status="Success"),
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


def collect_subscribed_skus(
    auth: AuthContext,
    *,
    dry_run: bool = True,
) -> list[SubscribedSku]:
    """Return subscribed SKUs.

    Dry-run returns a synthetic E5-like entitlement set so the engine and
    report can be exercised without a tenant.
    """
    if dry_run or auth.mode == AuthMode.DRY_RUN:
        return list(_DEMO_SKUS)

    raise NotImplementedError(
        "Live Graph SKU collection is not implemented in this scaffold. "
        "Use --dry-run or wait for the collector milestone."
    )

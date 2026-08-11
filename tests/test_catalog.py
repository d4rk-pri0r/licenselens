from licenselens.catalog.loader import (
    capability_summaries_for,
    load_capabilities,
    resolve_owned_capabilities,
)
from licenselens.models import Capability, ServicePlan, SubscribedSku


def test_load_capabilities():
    caps = load_capabilities()
    ids = {c.id for c in caps}
    assert "entra_id_p2" in ids
    assert "microsoft_sentinel" in ids
    entra = next(c for c in caps if c.id == "entra_id_p2")
    assert "admin" in entra.plain_name.lower()
    assert entra.outcome
    assert entra.why_it_matters


def test_resolve_owned_capabilities_from_demo_plans():
    caps = load_capabilities()
    skus = [
        SubscribedSku(
            sku_part_number="SPE_E5",
            service_plans=[
                ServicePlan(service_plan_name="AAD_PREMIUM_P2", provisioning_status="Success"),
                ServicePlan(
                    service_plan_name="THREAT_INTELLIGENCE",
                    provisioning_status="Success",
                ),
            ],
        )
    ]
    owned = resolve_owned_capabilities(caps, skus)
    assert "entra_id_p2" in owned
    assert "identity_protection" in owned
    assert "defender_office_p2" in owned


def test_capability_summaries_include_entitlement_provenance():
    # Given capabilities matched by two SKUs and every service-plan status class.
    capabilities = [
        Capability(
            id="provenance",
            name="Provenance",
            service_plan_names=[
                "SUCCESS_PLAN",
                "ENABLED_PLAN",
                "EMPTY_PLAN",
                "DISABLED_PLAN",
                "ERROR_PLAN",
                "PENDING_PLAN",
            ],
            sku_part_numbers=["SKU_B", "SKU_A"],
        )
    ]
    skus = [
        SubscribedSku(
            sku_part_number="SKU_B",
            service_plans=[
                ServicePlan(service_plan_name="ENABLED_PLAN", provisioning_status="Enabled"),
                ServicePlan(service_plan_name="PENDING_PLAN", provisioning_status="Pending"),
                ServicePlan(service_plan_name="EMPTY_PLAN"),
            ],
        ),
        SubscribedSku(
            sku_part_number="SKU_A",
            service_plans=[
                ServicePlan(service_plan_name="SUCCESS_PLAN", provisioning_status="Success"),
                ServicePlan(service_plan_name="DISABLED_PLAN", provisioning_status="Disabled"),
                ServicePlan(service_plan_name="ERROR_PLAN", provisioning_status="Error"),
            ],
        ),
    ]
    owned = resolve_owned_capabilities(capabilities, skus)

    # When summaries are built from the collected entitlements.
    summaries = capability_summaries_for(capabilities, owned, skus)

    # Then exact matching provenance is sorted and inactive plans are excluded.
    assert len(summaries) == 1
    assert summaries[0].matched_skus == ["SKU_A", "SKU_B"]
    assert summaries[0].matched_service_plans == [
        "EMPTY_PLAN",
        "ENABLED_PLAN",
        "SUCCESS_PLAN",
    ]

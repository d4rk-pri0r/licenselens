from licenselens.catalog.loader import load_capabilities, resolve_owned_capabilities
from licenselens.models import ServicePlan, SubscribedSku


def test_load_capabilities():
    caps = load_capabilities()
    ids = {c.id for c in caps}
    assert "entra_id_p2" in ids
    assert "microsoft_sentinel" in ids


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

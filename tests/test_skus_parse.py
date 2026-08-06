from licenselens.collectors.skus import skus_from_graph_values


def test_parse_subscribed_skus_graph_shape():
    values = [
        {
            "skuId": "sku-1",
            "skuPartNumber": "SPE_E5",
            "capabilityStatus": "Enabled",
            "consumedUnits": 10,
            "prepaidUnits": {"enabled": 25},
            "servicePlans": [
                {
                    "servicePlanId": "plan-1",
                    "servicePlanName": "AAD_PREMIUM_P2",
                    "provisioningStatus": "Success",
                },
                {
                    "servicePlanId": "plan-2",
                    "servicePlanName": "THREAT_INTELLIGENCE",
                    "provisioningStatus": "Success",
                },
            ],
        }
    ]
    skus = skus_from_graph_values(values)
    assert len(skus) == 1
    assert skus[0].sku_part_number == "SPE_E5"
    assert skus[0].prepaid_units == 25
    assert skus[0].consumed_units == 10
    names = {p.service_plan_name for p in skus[0].service_plans}
    assert names == {"AAD_PREMIUM_P2", "THREAT_INTELLIGENCE"}

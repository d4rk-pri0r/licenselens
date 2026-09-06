"""WS4-C: MDI sensor/health collector hashes names."""

from __future__ import annotations

from licenselens.collectors.device_hash import hash_device_label
from licenselens.collectors.mdi_health import collect_mdi_health
from tests.fake_clients import FakeGraphClient, ok


def test_mdi_health_hashes_display_and_domain() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/security/identities/sensors",
        ok(
            {
                "value": [
                    {
                        "id": "s1",
                        "displayName": "DC1",
                        "domainName": "corp.example",
                        "healthStatus": "healthy",
                        "deploymentStatus": "upToDate",
                        "openHealthIssuesCount": 0,
                        "sensorType": "domainControllerIntegrated",
                    }
                ]
            }
        ),
    )
    fake.register_list(
        "/security/identities/healthIssues",
        ok({"value": [{"id": "i1", "status": "open", "healthIssueType": "sensor"}]}),
    )
    bundle = collect_mdi_health(fake)
    assert bundle["direct"] is True
    assert bundle["sensor_count"] == 1
    assert bundle["unhealthy_count"] == 0
    assert bundle["open_health_issues"] == 1
    row = bundle["sensors"][0]
    assert row["displayName_hash"] == hash_device_label("DC1")
    assert row["domainName_hash"] == hash_device_label("corp.example")
    assert "DC1" not in str(bundle)
    assert "corp.example" not in str(bundle)


def test_mdi_disconnected_counts_unhealthy() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/security/identities/sensors",
        ok(
            {
                "value": [
                    {
                        "id": "s1",
                        "displayName": "DC1",
                        "healthStatus": "healthy",
                        "deploymentStatus": "disconnected",
                    }
                ]
            }
        ),
    )
    fake.register_list("/security/identities/healthIssues", ok({"value": []}))
    bundle = collect_mdi_health(fake)
    assert bundle["unhealthy_count"] == 1
    assert bundle["sensors"][0]["unhealthy"] is True

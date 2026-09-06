"""WS4-A: Entra devices + MDE inventory hashing."""

from __future__ import annotations

from datetime import UTC, datetime

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS, AuthContext, AuthMode
from licenselens.collectors.device_hash import hash_device_label
from licenselens.collectors.entra_devices import collect_entra_devices
from licenselens.collectors.intune import collect_intune_managed_devices
from licenselens.collectors.mde import collect_mde_machines_inventory
from tests.fake_clients import FakeGraphClient, FakeMdeClient, ok


def test_device_read_all_required() -> None:
    assert "Device.Read.All" in REQUIRED_GRAPH_APP_PERMISSIONS
    assert len(REQUIRED_GRAPH_APP_PERMISSIONS) == 22


def test_entra_devices_hashes_display_name() -> None:
    fake = FakeGraphClient()
    fake.register_list(
        "/devices",
        ok(
            {
                "value": [
                    {
                        "id": "1",
                        "deviceId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        "displayName": "LAPTOP-SECRET",
                        "accountEnabled": True,
                    }
                ]
            }
        ),
    )
    bundle = collect_entra_devices(fake)
    assert "LAPTOP-SECRET" not in str(bundle)
    assert bundle["devices"][0]["displayName_hash"] == hash_device_label("LAPTOP-SECRET")


def test_intune_select_includes_aad_device_id() -> None:
    fake = FakeGraphClient()
    captured: dict[str, object] = {}

    def handler(path: str, params: dict | None = None) -> dict:
        captured["params"] = params
        return {"value": [{"id": "d1", "deviceName": "HOST-1", "azureADDeviceId": "guid"}]}

    fake.register_list("/deviceManagement/managedDevices", handler)
    rows = collect_intune_managed_devices(fake)
    select = str((captured.get("params") or {}).get("$select") or "")
    assert "azureADDeviceId" in select
    assert "lastSyncDateTime" in select
    assert "HOST-1" not in str(rows)
    assert rows[0]["deviceName_hash"] == hash_device_label("HOST-1")


def test_mde_inventory_hashes_names_and_filters_last_seen() -> None:
    fake = FakeMdeClient()
    captured: dict[str, object] = {}

    def handler(path: str, params: dict | None = None) -> dict:
        captured["params"] = params
        return {
            "value": [
                {
                    "id": "m1",
                    "aadDeviceId": "guid",
                    "computerDnsName": "workstation.contoso.com",
                    "onboardingStatus": "Onboarded",
                    "lastSeen": "2026-09-01T00:00:00Z",
                }
            ]
        }

    fake.register_get("/machines", handler)
    auth = AuthContext(mode=AuthMode.CLIENT_SECRET)
    bundle = collect_mde_machines_inventory(auth, client=fake, now=datetime(2026, 9, 6, tzinfo=UTC))
    params = captured.get("params") or {}
    assert "lastSeen gt" in str(params.get("$filter"))
    assert "workstation.contoso.com" not in str(bundle)
    assert bundle["machines"][0]["computerDnsName_hash"] == hash_device_label(
        "workstation.contoso.com"
    )

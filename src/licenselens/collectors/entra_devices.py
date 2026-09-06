"""Collect Entra ID registered devices (bounded inventory)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.device_hash import hash_device_label
from licenselens.graph import GraphClient

_SELECT = (
    "id,deviceId,displayName,operatingSystem,operatingSystemVersion,"
    "approximateLastSignInDateTime,isManaged,isCompliant,trustType,accountEnabled"
)

DEMO_ENTRA_DEVICES: dict[str, Any] = {
    "devices": [],
    "count": 0,
    "truncated": False,
    "window_days": 30,
}


def collect_entra_devices(
    client: GraphClient,
    *,
    max_pages: int = 30,
) -> dict[str, Any]:
    """Return hashed Entra device inventory (no raw displayName)."""
    rows = client.get_list(
        "/devices",
        params={"$select": _SELECT, "$top": "999"},
        max_pages=max_pages,
    )
    truncated = len(rows) >= max_pages * 999
    devices: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        devices.append(
            {
                "id": str(item.get("id") or ""),
                "deviceId": str(item.get("deviceId") or ""),
                "displayName_hash": hash_device_label(item.get("displayName")),
                "operatingSystem": item.get("operatingSystem"),
                "operatingSystemVersion": item.get("operatingSystemVersion"),
                "approximateLastSignInDateTime": item.get("approximateLastSignInDateTime"),
                "isManaged": item.get("isManaged"),
                "isCompliant": item.get("isCompliant"),
                "trustType": item.get("trustType"),
                "accountEnabled": item.get("accountEnabled"),
            }
        )
    return {
        "devices": devices,
        "count": len(devices),
        "truncated": truncated,
        "window_days": 30,
    }

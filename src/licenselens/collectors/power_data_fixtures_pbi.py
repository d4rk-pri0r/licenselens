"""Power BI offline tenant-settings fixture payloads (pure data)."""

from __future__ import annotations

from typing import Final

from licenselens.schema_contracts import JsonValue


def _setting(
    surface: str,
    name: str,
    *,
    enabled: bool,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    props: dict[str, object] = {"enabled": enabled, "settingName": name}
    if extra:
        props.update(extra)
    return {
        "surface": surface,
        "status": "ok",
        "reason": "",
        "raw_count": 1,
        "items": [
            {
                "name": name,
                "identity": name,
                "kind": "effective",
                "enabled": enabled,
                "properties": props,
                "assignments": [],
            }
        ],
    }


DEMO_PBI_TENANT_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "pbi_tenant",
    "module": "MicrosoftPowerBIMgmt",
    "collection": "power_bi_tenant",
    "surfaces": {
        "publish_to_web": _setting("publish_to_web", "PublishToWeb", enabled=False),
        "guest_access": _setting(
            "guest_access",
            "AllowAzureAdGuestUserAccess",
            enabled=False,
        ),
        "external_invite": _setting(
            "external_invite",
            "AllowExternalUsersToCollaborateThroughItemSharing",
            enabled=False,
        ),
        "service_principal_api": _setting(
            "service_principal_api",
            "servicePrincipalsCanCallFabricPublicAPIs",
            enabled=True,
            extra={"securityGroups": ["sg-pbi-sp"]},
        ),
        "service_principal_profiles": _setting(
            "service_principal_profiles",
            "AllowServicePrincipalsCreateAndUseProfiles",
            enabled=False,
        ),
        "resource_key_auth": _setting(
            "resource_key_auth",
            "BlockResourceKeyAuthentication",
            enabled=True,
        ),
        "python_r_visuals": _setting(
            "python_r_visuals",
            "InteractWithRVisuals",
            enabled=False,
        ),
        "sensitivity_labels": _setting(
            "sensitivity_labels",
            "allowUsersToApplySensitivityLabelsForContent",
            enabled=True,
        ),
        "export_data": _setting(
            "export_data",
            "ExportToExcel",
            enabled=False,
        ),
    },
}

# Negative fixture: Get-* tenant setting cmdlet missing (module-version drift).
DEMO_PBI_MODULE_DRIFT_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "pbi_tenant",
    "module": "MicrosoftPowerBIMgmt",
    "collection": "power_bi_tenant",
    "surfaces": {
        name: {
            "surface": name,
            "status": "unsupported",
            "reason": (
                "unsupported: no Get-PowerBITenantSetting/Get-FabricTenantSetting "
                "in installed module (portal or admin REST; module-version drift)"
            ),
            "raw_count": 0,
            "items": [],
        }
        for name in (
            "publish_to_web",
            "guest_access",
            "external_invite",
            "service_principal_api",
            "service_principal_profiles",
            "resource_key_auth",
            "python_r_visuals",
            "sensitivity_labels",
            "export_data",
        )
    },
}

__all__ = [
    "DEMO_PBI_MODULE_DRIFT_PAYLOAD",
    "DEMO_PBI_TENANT_PAYLOAD",
]

"""Teams offline fixture payloads (pure data)."""

from __future__ import annotations

from typing import Final

from licenselens.schema_contracts import JsonValue

DEMO_TEAMS_MEETING_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "teams_meeting",
    "module": "MicrosoftTeams",
    "collection": "teams_meeting",
    "surfaces": {
        "meeting_policies": {
            "surface": "meeting_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 2,
            "items": [
                {
                    "name": "Global",
                    "identity": "Global",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "AllowExternalParticipantGiveRequestControl": False,
                        "AllowAnonymousUsersToStartMeeting": False,
                        "AutoAdmittedUsers": "EveryoneInCompany",
                        "AllowPSTNUsersToBypassLobby": False,
                        "AllowCloudRecording": False,
                    },
                    "assignments": ["All"],
                },
                {
                    "name": "ExecRecording",
                    "identity": "Tag:ExecRecording",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "AllowExternalParticipantGiveRequestControl": False,
                        "AllowAnonymousUsersToStartMeeting": False,
                        "AutoAdmittedUsers": "EveryoneInCompany",
                        "AllowPSTNUsersToBypassLobby": False,
                        "AllowCloudRecording": True,
                    },
                    "assignments": ["sg-executives@contoso.com"],
                },
            ],
        },
        "broadcast_policies": {
            "surface": "broadcast_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 2,
            "items": [
                {
                    "name": "Global",
                    "identity": "Global",
                    "kind": "default",
                    "enabled": True,
                    "properties": {"BroadcastRecordingMode": "UserOverride"},
                    "assignments": ["All"],
                },
                {
                    "name": "AlwaysRecordEvents",
                    "identity": "Tag:AlwaysRecordEvents",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {"BroadcastRecordingMode": "AlwaysEnabled"},
                    "assignments": ["sg-comms@contoso.com"],
                },
            ],
        },
    },
    "collected_at": "2026-08-14T00:00:00Z",
}

DEMO_TEAMS_FEDERATION_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "teams_federation",
    "module": "MicrosoftTeams",
    "collection": "teams_federation",
    "surfaces": {
        "federation": {
            "surface": "federation",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "TenantFederation",
                    "identity": "Global",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "AllowFederatedUsers": True,
                        "AllowedDomains": ["partner.gov"],
                        "BlockedDomains": [],
                        "SharedSipAddressSpace": False,
                    },
                    "assignments": [],
                }
            ],
        },
        "unmanaged_users": {
            "surface": "unmanaged_users",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "national_cloud_limited": True,
            "items": [
                {
                    "name": "Global",
                    "identity": "Global",
                    "kind": "default",
                    "enabled": False,
                    "properties": {
                        "EnableTeamsConsumerAccess": False,
                        "EnableTeamsConsumerInbound": False,
                    },
                    "assignments": ["All"],
                }
            ],
        },
    },
    "collected_at": "2026-08-14T00:00:00Z",
}

DEMO_TEAMS_CLIENT_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "teams_client",
    "module": "MicrosoftTeams",
    "collection": "teams_client",
    "surfaces": {
        "email_integration": {
            "surface": "email_integration",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "national_cloud_limited": True,
            "items": [
                {
                    "name": "ClientConfiguration",
                    "identity": "Global",
                    "kind": "effective",
                    "enabled": False,
                    "properties": {
                        "AllowEmailIntoChannel": False,
                        "RestrictedSenderList": None,
                    },
                    "assignments": [],
                }
            ],
        },
        "guest_access": {
            "surface": "guest_access",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "national_cloud_limited": True,
            "items": [
                {
                    "name": "GuestAccess",
                    "identity": "Global",
                    "kind": "effective",
                    "enabled": False,
                    "properties": {
                        "AllowGuestUser": False,
                        "AllowGuestCalling": False,
                        "AllowGuestChat": False,
                    },
                    "assignments": [],
                }
            ],
        },
    },
    "collected_at": "2026-08-14T00:00:00Z",
}

DEMO_TEAMS_APPS_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "teams_apps",
    "module": "MicrosoftTeams",
    "collection": "teams_apps",
    "surfaces": {
        "app_permission_policies": {
            "surface": "app_permission_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 2,
            "items": [
                {
                    "name": "Global",
                    "identity": "Global",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "DefaultCatalogAppsType": "BlockedAppList",
                        "GlobalCatalogAppsType": "BlockedAppList",
                        "PrivateCatalogAppsType": "BlockedAppList",
                    },
                    "assignments": ["All"],
                },
                {
                    "name": "PowerUsers",
                    "identity": "Tag:PowerUsers",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "DefaultCatalogAppsType": "AllowedAppList",
                        "GlobalCatalogAppsType": "BlockedAppList",
                        "PrivateCatalogAppsType": "BlockedAppList",
                    },
                    "assignments": ["sg-power-users@contoso.com"],
                },
            ],
        },
        "app_settings_v2": {
            "surface": "app_settings_v2",
            "status": "unsupported",
            "reason": "Get-M365UnifiedTenantSettings not present (v2 org-wide app settings)",
            "raw_count": 0,
            "national_cloud_limited": True,
            "items": [],
        },
    },
    "collected_at": "2026-08-14T00:00:00Z",
}

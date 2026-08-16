"""SharePoint/OneDrive offline fixture payloads (pure data)."""

from __future__ import annotations

from typing import Final

from licenselens.schema_contracts import JsonValue

DEMO_SPO_TENANT_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "spo_tenant",
    "module": "Microsoft.Online.SharePoint.PowerShell",
    "collection": "sharepoint_tenant",
    "surfaces": {
        "sharing_capability": {
            "surface": "sharing_capability",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "TenantSharing",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "SharingCapability": "ExistingExternalUserSharingOnly",
                        "ShowPeoplePickerSuggestionsForGuestUsers": False,
                    },
                    "assignments": [],
                }
            ],
        },
        "onedrive_sharing": {
            "surface": "onedrive_sharing",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "OneDriveSharing",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "OneDriveSharingCapability": "ExistingExternalUserSharingOnly",
                    },
                    "assignments": [],
                }
            ],
        },
        "domain_restrictions": {
            "surface": "domain_restrictions",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "DomainRestrictions",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "SharingDomainRestrictionMode": "AllowList",
                        "SharingAllowedDomainList": "contoso.com partner.gov",
                        "SharingBlockedDomainList": "",
                    },
                    "assignments": ["sg-external-share@contoso.com"],
                }
            ],
        },
        "default_link": {
            "surface": "default_link",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "DefaultLink",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "DefaultSharingLinkType": "Direct",
                        "DefaultLinkPermission": "View",
                    },
                    "assignments": [],
                }
            ],
        },
        "anyone_link_expiration": {
            "surface": "anyone_link_expiration",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "AnyoneLinkExpiration",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "RequireAnonymousLinksExpireInDays": 30,
                        "SharingCapability": "ExistingExternalUserSharingOnly",
                    },
                    "assignments": [],
                }
            ],
        },
        "anyone_link_permissions": {
            "surface": "anyone_link_permissions",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "AnyoneLinkPermissions",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "FileAnonymousLinkType": "View",
                        "FolderAnonymousLinkType": "View",
                    },
                    "assignments": [],
                }
            ],
        },
        "reauth_days": {
            "surface": "reauth_days",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "EmailAttestationReAuth",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "EmailAttestationRequired": True,
                        "EmailAttestationReAuthDays": 30,
                    },
                    "assignments": [],
                }
            ],
        },
        "unmanaged_device_policy": {
            "surface": "unmanaged_device_policy",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "UnmanagedDevicePolicy",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "ConditionalAccessPolicy": "BlockAccess",
                    },
                    "assignments": [],
                }
            ],
        },
    },
    "collected_at": "2026-08-14T00:00:00Z",
}

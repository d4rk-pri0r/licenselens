"""Power Platform offline multi-environment fixture payloads (pure data)."""

from __future__ import annotations

from typing import Final

from licenselens.schema_contracts import JsonValue

DEMO_PP_TENANT_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "pp_tenant",
    "module": "Microsoft.PowerApps.Administration.PowerShell",
    "collection": "power_platform_tenant",
    "surfaces": {
        "environment_creation": {
            "surface": "environment_creation",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "EnvironmentCreation",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "disableEnvironmentCreationByNonAdminUsers": True,
                        "disableTrialEnvironmentCreationByNonAdminUsers": True,
                    },
                    "assignments": [],
                }
            ],
        },
        "power_pages": {
            "surface": "power_pages",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "PowerPagesCreation",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {"disablePortalsCreationByNonAdminUsers": True},
                    "assignments": [],
                }
            ],
        },
        "share_with_everyone": {
            "surface": "share_with_everyone",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "ShareWithEveryone",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {"disableShareWithEveryone": True},
                    "assignments": [],
                }
            ],
        },
        "content_security_policy": {
            "surface": "content_security_policy",
            "status": "unsupported",
            "reason": (
                "portal-only: CSP is per-environment Privacy+Security (Dataverse); "
                "no tenant Get-* cmdlet"
            ),
            "raw_count": 0,
            "items": [],
            "portal_only": True,
        },
    },
}

DEMO_PP_ENVIRONMENTS_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "pp_environments",
    "module": "Microsoft.PowerApps.Administration.PowerShell",
    "collection": "power_platform_environments",
    "surfaces": {
        "environments": {
            "surface": "environments",
            "status": "ok",
            "reason": "",
            "raw_count": 3,
            "items": [
                {
                    "name": "contoso (default)",
                    "identity": "env-default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "IsDefault": True,
                        "EnvironmentType": "Default",
                        "HasDataverse": True,
                        "Location": "unitedstates",
                    },
                    "assignments": [],
                },
                {
                    "name": "Prod Finance",
                    "identity": "env-prod-finance",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "IsDefault": False,
                        "EnvironmentType": "Production",
                        "HasDataverse": True,
                        "Location": "unitedstates",
                    },
                    "assignments": [],
                },
                {
                    "name": "Sandbox No Dataverse",
                    "identity": "env-sandbox-nodv",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "IsDefault": False,
                        "EnvironmentType": "Sandbox",
                        "HasDataverse": False,
                        "Location": "europe",
                    },
                    "assignments": [],
                },
            ],
        }
    },
}

DEMO_PP_DLP_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "pp_dlp",
    "module": "Microsoft.PowerApps.Administration.PowerShell",
    "collection": "power_platform_dlp",
    "surfaces": {
        "dlp_policies": {
            "surface": "dlp_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 2,
            "items": [
                {
                    "name": "Default Environment Lockdown",
                    "identity": "dlp-default",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "EnvironmentType": "OnlyEnvironments",
                        "EnvironmentCount": 1,
                        "Environments": ["env-default"],
                    },
                    "assignments": ["env-default"],
                },
                {
                    "name": "All Non-Default",
                    "identity": "dlp-all-others",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "EnvironmentType": "ExceptEnvironments",
                        "EnvironmentCount": 1,
                        "Environments": ["env-default"],
                    },
                    "assignments": ["env-default"],
                },
            ],
        }
    },
}

DEMO_PP_ISOLATION_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "pp_isolation",
    "module": "Microsoft.PowerApps.Administration.PowerShell",
    "collection": "power_platform_isolation",
    "surfaces": {
        "tenant_isolation": {
            "surface": "tenant_isolation",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "TenantIsolation",
                    "identity": "tenant",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "isDisabled": False,
                        "isolationEnabled": True,
                        "allowedTenants": ["11111111-1111-1111-1111-111111111111"],
                    },
                    "assignments": [],
                }
            ],
        }
    },
}

__all__ = [
    "DEMO_PP_DLP_PAYLOAD",
    "DEMO_PP_ENVIRONMENTS_PAYLOAD",
    "DEMO_PP_ISOLATION_PAYLOAD",
    "DEMO_PP_TENANT_PAYLOAD",
]

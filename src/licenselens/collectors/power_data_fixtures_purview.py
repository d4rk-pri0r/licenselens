"""Purview governance offline fixture payloads (pure data)."""

from __future__ import annotations

from typing import Final

from licenselens.schema_contracts import JsonValue

DEMO_PURVIEW_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "purview_governance",
    "module": "ExchangeOnlineManagement",
    "collection": "purview_governance",
    "surfaces": {
        "dlp_policies": {
            "surface": "dlp_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "U.S. Financial Data",
                    "identity": "dlp-fin",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "Mode": "Enable",
                        "Enabled": True,
                        "Workload": "Exchange, SharePoint, OneDrive, Teams",
                        "DistributionStatus": "Success",
                    },
                    "assignments": [],
                }
            ],
        },
        "dlp_rules": {
            "surface": "dlp_rules",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Block external finance",
                    "identity": "rule-fin",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "Disabled": False,
                        "Mode": "Enforce",
                        "Policy": "U.S. Financial Data",
                        "BlockAccess": True,
                        "NotifyUser": True,
                    },
                    "assignments": [],
                }
            ],
        },
        "sensitivity_labels": {
            "surface": "sensitivity_labels",
            "status": "ok",
            "reason": "",
            "raw_count": 2,
            "items": [
                {
                    "name": "Confidential",
                    "identity": "label-conf",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "DisplayName": "Confidential",
                        "Priority": 2,
                        "Disabled": False,
                    },
                    "assignments": [],
                },
                {
                    "name": "Public",
                    "identity": "label-pub",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "DisplayName": "Public",
                        "Priority": 0,
                        "Disabled": False,
                    },
                    "assignments": [],
                },
            ],
        },
        "label_policies": {
            "surface": "label_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Global labels",
                    "identity": "lp-global",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "Enabled": True,
                        "ExchangeLocation": "All",
                        "ModernGroupLocation": "All",
                        "Settings": ["DefaultLabelId:label-conf", "Mandatory:true"],
                    },
                    "assignments": [],
                }
            ],
        },
        "retention_policies": {
            "surface": "retention_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "7-year mailbox",
                    "identity": "ret-7y",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "Enabled": True,
                        "Mode": "Enable",
                        "Workload": "Exchange",
                        "RestrictiveRetention": True,
                    },
                    "assignments": [],
                }
            ],
        },
        "retention_rules": {
            "surface": "retention_rules",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Keep 2555 days",
                    "identity": "retrule-7y",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "Disabled": False,
                        "RetentionDuration": 2555,
                        "RetentionComplianceAction": "Keep",
                        "Policy": "7-year mailbox",
                    },
                    "assignments": [],
                }
            ],
        },
        "audit_config": {
            "surface": "audit_config",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "AdminAuditLogConfig",
                    "identity": "AdminAuditLogConfig",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {
                        "UnifiedAuditLogIngestionEnabled": True,
                        "AdminAuditLogEnabled": True,
                    },
                    "assignments": [],
                }
            ],
        },
    },
}

# Absent configuration (readable API, zero policies) vs unreadable.
DEMO_PURVIEW_ABSENT_DLP_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "purview_governance",
    "module": "ExchangeOnlineManagement",
    "collection": "purview_governance",
    "surfaces": {
        "dlp_policies": {
            "surface": "dlp_policies",
            "status": "ok",
            "reason": "absent: no dlp_policies configured",
            "raw_count": 0,
            "items": [],
        },
        "dlp_rules": {
            "surface": "dlp_rules",
            "status": "ok",
            "reason": "absent: no dlp_rules configured",
            "raw_count": 0,
            "items": [],
        },
        "sensitivity_labels": {
            "surface": "sensitivity_labels",
            "status": "ok",
            "reason": "absent: no sensitivity_labels configured",
            "raw_count": 0,
            "items": [],
        },
        "label_policies": {
            "surface": "label_policies",
            "status": "ok",
            "reason": "absent: no label_policies configured",
            "raw_count": 0,
            "items": [],
        },
        "retention_policies": {
            "surface": "retention_policies",
            "status": "ok",
            "reason": "absent: no retention_policies configured",
            "raw_count": 0,
            "items": [],
        },
        "retention_rules": {
            "surface": "retention_rules",
            "status": "ok",
            "reason": "absent: no retention_rules configured",
            "raw_count": 0,
            "items": [],
        },
        "audit_config": {
            "surface": "audit_config",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "AdminAuditLogConfig",
                    "identity": "AdminAuditLogConfig",
                    "kind": "effective",
                    "enabled": False,
                    "properties": {
                        "UnifiedAuditLogIngestionEnabled": False,
                        "AdminAuditLogEnabled": False,
                    },
                    "assignments": [],
                }
            ],
        },
    },
}

__all__ = [
    "DEMO_PURVIEW_ABSENT_DLP_PAYLOAD",
    "DEMO_PURVIEW_PAYLOAD",
]

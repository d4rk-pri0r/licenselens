"""Dry-run / fixture payloads for Exchange and Security/Compliance collection."""

from __future__ import annotations

from typing import Final

from licenselens.collectors.exchange_models import ExchangeBundle
from licenselens.collectors.exchange_normalize import normalize_adapter_payload
from licenselens.schema_contracts import JsonValue

DEMO_THREAT_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "exo_threat_policies",
    "module": "ExchangeOnlineManagement",
    "collection": "exchange_threat_policies",
    "surfaces": {
        "safe_links": {
            "surface": "safe_links",
            "status": "ok",
            "reason": "",
            "raw_count": 2,
            "items": [
                {
                    "name": "Standard Preset Security Policy",
                    "identity": "Standard Preset Security Policy",
                    "kind": "preset_standard",
                    "enabled": True,
                    "properties": {
                        "EnableSafeLinksForEmail": True,
                        "EnableSafeLinksForTeams": True,
                        "EnableSafeLinksForOffice": True,
                        "ScanUrls": True,
                        "DeliverMessageAfterScan": True,
                        "TrackClicks": True,
                    },
                    "assignments": ["All"],
                },
                {
                    "name": "Custom Safe Links",
                    "identity": "Custom Safe Links",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {"EnableSafeLinksForEmail": True},
                    "assignments": ["finance@contoso.com"],
                },
            ],
        },
        "safe_attachments": {
            "surface": "safe_attachments",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Standard Preset Security Policy",
                    "identity": "Standard Preset Security Policy",
                    "kind": "preset_standard",
                    "enabled": True,
                    "properties": {"Enable": True, "Action": "Block"},
                    "assignments": ["All"],
                }
            ],
        },
        "preset_security": {
            "surface": "preset_security",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Standard Preset Security Policy",
                    "identity": "Standard Preset Security Policy",
                    "kind": "preset_standard",
                    "enabled": True,
                    "properties": {"State": "Enabled", "Priority": 0},
                    "assignments": [],
                }
            ],
        },
        "anti_malware": {
            "surface": "anti_malware",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Default",
                    "identity": "Default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {"EnableFileFilter": True, "ZapEnabled": True},
                    "assignments": [],
                }
            ],
        },
        "anti_phish": {
            "surface": "anti_phish",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Office365 AntiPhish Default",
                    "identity": "Office365 AntiPhish Default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "EnableSpoofIntelligence": True,
                        "EnableMailboxIntelligence": True,
                        "EnableMailboxIntelligenceProtection": True,
                        "EnableFirstContactSafetyTips": True,
                        "EnableSimilarUsersSafetyTips": True,
                        "EnableSimilarDomainsSafetyTips": True,
                        "EnableUnusualCharactersSafetyTips": True,
                    },
                    "assignments": [],
                }
            ],
        },
        "impersonation": {
            "surface": "impersonation",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Office365 AntiPhish Default",
                    "identity": "Office365 AntiPhish Default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "EnableTargetedUserProtection": True,
                        "EnableTargetedDomainsProtection": True,
                        "EnableOrganizationDomainsProtection": True,
                    },
                    "assignments": [],
                }
            ],
        },
        "anti_spam": {
            "surface": "anti_spam",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Default",
                    "identity": "Default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "SpamAction": "Quarantine",
                        "HighConfidenceSpamAction": "Quarantine",
                        "PhishSpamAction": "Quarantine",
                        "HighConfidencePhishAction": "Quarantine",
                        "BulkSpamAction": "Quarantine",
                        "AllowedSenders": [],
                        "AllowedSenderDomains": [],
                    },
                    "assignments": [],
                }
            ],
        },
        "connection_filter": {
            "surface": "connection_filter",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Default",
                    "identity": "Default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "IPAllowList": [],
                        "IPBlockList": [],
                        "EnableSafeList": False,
                    },
                    "assignments": [],
                }
            ],
        },
        "outbound_spam": {
            "surface": "outbound_spam",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Default",
                    "identity": "Default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {"AutoForwardingEnabled": False, "IsDefault": True},
                    "assignments": [],
                }
            ],
        },
        "atp_global": {
            "surface": "atp_global",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Default",
                    "identity": "Default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "EnableATPForSPOTeamsODB": True,
                        "EnableSafeDocs": True,
                    },
                    "assignments": [],
                }
            ],
        },
        "quarantine": {
            "surface": "quarantine",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "DefaultFullAccessPolicy",
                    "identity": "DefaultFullAccessPolicy",
                    "kind": "default",
                    "enabled": True,
                    "properties": {"EsnEnabled": True},
                    "assignments": [],
                }
            ],
        },
    },
    "collected_at": "2026-08-14T00:00:00Z",
}

DEMO_MAILFLOW_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "exo_remote_domains",
    "module": "ExchangeOnlineManagement",
    "collection": "exchange_remote_domains",
    "surfaces": {
        "remote_domains": {
            "surface": "remote_domains",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Default",
                    "identity": "Default",
                    "kind": "default",
                    "enabled": True,
                    "properties": {"DomainName": "*", "AutoForwardEnabled": False},
                    "assignments": [],
                }
            ],
        }
    },
}

DEMO_TRANSPORT_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "exo_transport",
    "module": "ExchangeOnlineManagement",
    "collection": "exchange_transport",
    "surfaces": {
        "transport_rules": {
            "surface": "transport_rules",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "External sender warning",
                    "identity": "External sender warning",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "State": "Enabled",
                        "FromScope": "NotInOrganization",
                        "PrependSubject": "[External]",
                    },
                    "assignments": [],
                }
            ],
        },
        "external_warning": {
            "surface": "external_warning",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "OrganizationConfig",
                    "identity": "OrganizationConfig",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {"MailTipsExternalRecipientsTipsEnabled": True},
                    "assignments": [],
                }
            ],
        },
    },
}

DEMO_SMTP_AUTH_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "exo_smtp_auth",
    "module": "ExchangeOnlineManagement",
    "collection": "exchange_smtp_auth",
    "surfaces": {
        "smtp_auth": {
            "surface": "smtp_auth",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "TransportConfig",
                    "identity": "TransportConfig",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {"SmtpClientAuthenticationDisabled": True},
                    "assignments": [],
                }
            ],
        }
    },
}

DEMO_SHARING_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "exo_sharing",
    "module": "ExchangeOnlineManagement",
    "collection": "exchange_sharing",
    "surfaces": {
        "sharing_policies": {
            "surface": "sharing_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Default Sharing Policy",
                    "identity": "Default Sharing Policy",
                    "kind": "default",
                    "enabled": True,
                    "properties": {
                        "Domains": ["partner.example.com:CalendarSharingFreeBusySimple"],
                        "Default": True,
                    },
                    "assignments": [],
                }
            ],
        }
    },
}

DEMO_ACCEPTED_DOMAINS_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "exo_accepted_domains",
    "module": "ExchangeOnlineManagement",
    "collection": "exchange_accepted_domains",
    "surfaces": {
        "accepted_domains": {
            "surface": "accepted_domains",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "contoso.com",
                    "identity": "contoso.com",
                    "kind": "default",
                    "enabled": True,
                    "properties": {"DomainName": "contoso.com", "DomainType": "Authoritative"},
                    "assignments": [],
                }
            ],
        }
    },
}

DEMO_DKIM_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "exo_dkim",
    "module": "ExchangeOnlineManagement",
    "collection": "exchange_dkim",
    "surfaces": {
        "dkim": {
            "surface": "dkim",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "contoso.com",
                    "identity": "contoso.com",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {"Domain": "contoso.com", "Enabled": True, "Status": "Valid"},
                    "assignments": [],
                }
            ],
        }
    },
}

DEMO_AUDIT_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "exo_audit",
    "module": "ExchangeOnlineManagement",
    "collection": "exchange_audit",
    "surfaces": {
        "organization_audit": {
            "surface": "organization_audit",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "OrganizationConfig",
                    "identity": "OrganizationConfig",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {"AuditDisabled": False},
                    "assignments": [],
                }
            ],
        },
        "mailbox_audit": {
            "surface": "mailbox_audit",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "AdminAuditLogConfig",
                    "identity": "AdminAuditLogConfig",
                    "kind": "effective",
                    "enabled": True,
                    "properties": {"UnifiedAuditLogIngestionEnabled": True},
                    "assignments": [],
                }
            ],
        },
    },
}

DEMO_COMPLIANCE_PAYLOAD: Final[dict[str, JsonValue]] = {
    "adapter": "scc_compliance",
    "module": "ExchangeOnlineManagement",
    "collection": "scc_compliance",
    "surfaces": {
        "dlp_policies": {
            "surface": "dlp_policies",
            "status": "ok",
            "reason": "",
            "raw_count": 1,
            "items": [
                {
                    "name": "Protect PII",
                    "identity": "Protect PII",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {
                        "Mode": "Enable",
                        "Workload": "Exchange,SharePoint,OneDrive",
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
                    "name": "Block SSN and credit card",
                    "identity": "Block SSN and credit card",
                    "kind": "custom",
                    "enabled": True,
                    "properties": {"Disabled": False, "BlockAccess": True, "NotifyUser": True},
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
                    "properties": {"UnifiedAuditLogIngestionEnabled": True},
                    "assignments": [],
                }
            ],
        },
    },
}

DEMO_ADAPTER_PAYLOADS: Final[dict[str, dict[str, JsonValue]]] = {
    "exo_threat_policies": DEMO_THREAT_PAYLOAD,
    "exo_remote_domains": DEMO_MAILFLOW_PAYLOAD,
    "exo_transport": DEMO_TRANSPORT_PAYLOAD,
    "exo_smtp_auth": DEMO_SMTP_AUTH_PAYLOAD,
    "exo_sharing": DEMO_SHARING_PAYLOAD,
    "exo_accepted_domains": DEMO_ACCEPTED_DOMAINS_PAYLOAD,
    "exo_dkim": DEMO_DKIM_PAYLOAD,
    "exo_audit": DEMO_AUDIT_PAYLOAD,
    "scc_compliance": DEMO_COMPLIANCE_PAYLOAD,
}


def demo_exchange_evidence() -> dict[str, JsonValue]:
    """Dry-run evidence with direct threat/audit/compliance fixtures (no Secure Score)."""
    adapters = {
        name: normalize_adapter_payload(payload, adapter=name)
        for name, payload in DEMO_ADAPTER_PAYLOADS.items()
    }
    bundle = ExchangeBundle(adapters=adapters, direct=True, proxy=False)
    from licenselens.collectors.exchange import bundle_to_evidence

    return bundle_to_evidence(bundle)

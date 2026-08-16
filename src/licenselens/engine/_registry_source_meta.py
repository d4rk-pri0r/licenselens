from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from licenselens.engine.registry import Backend

type SourceMeta = tuple[Backend, tuple[str, ...], str, int]
type CollectorMeta = tuple[Backend, tuple[str, ...], tuple[str, ...]]

SOURCE_META: Final[Mapping[str, SourceMeta]] = MappingProxyType(
    {
        "access_review_definitions": (
            Backend.GRAPH,
            ("AccessReview.Read.All",),
            "graph:accessReviews",
            30,
        ),
        "access_packages": (
            Backend.GRAPH,
            ("EntitlementManagement.Read.All",),
            "graph:entitlementManagement.accessPackages",
            30,
        ),
        "admin_consent_request_policy": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            "graph:adminConsentRequestPolicy",
            30,
        ),
        "applications_bundle": (
            Backend.GRAPH,
            ("Application.Read.All", "Directory.Read.All"),
            "graph:applicationsBundle",
            45,
        ),
        "approved_guest_domains": (
            Backend.NOOP,
            (),
            "profile:approvedGuestDomains",
            5,
        ),
        "auth_methods_bundle": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            "graph:authMethodsBundle",
            30,
        ),
        "authorization_policy": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            "graph:authorizationPolicy",
            30,
        ),
        "break_glass_principal_ids": (
            Backend.NOOP,
            (),
            "profile:breakGlassPrincipals",
            5,
        ),
        "ca_policies": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            "graph:conditionalAccessPolicies",
            30,
        ),
        "domains": (
            Backend.GRAPH,
            ("Domain.Read.All", "Directory.Read.All"),
            "graph:domains",
            30,
        ),
        "guests_bundle": (
            Backend.GRAPH,
            ("Policy.Read.All", "User.Read.All"),
            "graph:guestsBundle",
            45,
        ),
        "mde_summary": (Backend.MDE, (), "mde:machines.summary", 45),
        "intune_bundle": (
            Backend.GRAPH,
            ("DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All"),
            "graph:intuneBundle",
            45,
        ),
        "mde_health": (Backend.MDE, (), "mde:machines.health", 45),
        "security_alerts_bundle": (
            Backend.GRAPH,
            ("SecurityIncident.Read.All", "SecurityAlert.Read.All"),
            "graph:securityAlertsBundle",
            30,
        ),
        "pim_policies_bundle": (
            Backend.GRAPH,
            ("RoleManagement.Read.Directory",),
            "graph:pimPoliciesBundle",
            30,
        ),
        "principal_directory": (
            Backend.GRAPH,
            ("Directory.Read.All",),
            "graph:directoryObjects",
            30,
        ),
        "purview_dlp": (
            Backend.PROXY,
            ("SecurityEvents.Read.All",),
            "proxy:purviewDlp",
            30,
        ),
        "recent_signin_user_ids": (
            Backend.GRAPH,
            ("AuditLog.Read.All",),
            "graph:signIns.success",
            45,
        ),
        "role_assignments": (
            Backend.GRAPH,
            ("RoleManagement.Read.Directory",),
            "graph:roleAssignments",
            30,
        ),
        "role_eligibilities": (
            Backend.GRAPH,
            ("RoleManagement.Read.Directory",),
            "graph:roleEligibilitySchedules",
            30,
        ),
        "security_defaults_policy": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            "graph:securityDefaults",
            30,
        ),
        "secure_score_controls": (
            Backend.GRAPH,
            ("SecurityEvents.Read.All",),
            "graph:secureScoreControls",
            30,
        ),
        "sentinel_rules": (Backend.ARM, (), "arm:sentinel.rules", 45),
        "sentinel_ueba": (Backend.ARM, (), "arm:sentinel.ueba", 45),
        "sentinel_data_connectors": (
            Backend.ARM,
            (),
            "arm:sentinel.dataConnectors",
            45,
        ),
        "sentinel_automation_rules": (
            Backend.ARM,
            (),
            "arm:sentinel.automationRules",
            45,
        ),
        "sentinel_workspace": (Backend.ARM, (), "arm:logAnalytics.workspace", 45),
        "defender_for_cloud_pricings": (
            Backend.ARM,
            (),
            "arm:defenderForCloud.pricings",
            30,
        ),
        "exchange_bundle": (Backend.NOOP, (), "powershell:exchangeBundle", 120),
        "dns_records": (Backend.NOOP, (), "dns:txtRecords", 30),
        "collaboration_bundle": (
            Backend.NOOP,
            (),
            "powershell:collaborationBundle",
            120,
        ),
        "power_data_bundle": (
            Backend.NOOP,
            (),
            "powershell:powerDataBundle",
            120,
        ),
    }
)

COLLECTOR_META: Final[Mapping[str, CollectorMeta]] = MappingProxyType(
    {
        "graph_access_reviews": (
            Backend.GRAPH,
            ("AccessReview.Read.All",),
            ("access_review_definitions",),
        ),
        "graph_entitlement_management": (
            Backend.GRAPH,
            ("EntitlementManagement.Read.All",),
            ("access_packages",),
        ),
        "graph_applications": (
            Backend.GRAPH,
            ("Application.Read.All", "Directory.Read.All"),
            ("applications_bundle",),
        ),
        "graph_auth_methods": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            ("auth_methods_bundle",),
        ),
        "graph_authorization": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            ("authorization_policy", "admin_consent_request_policy"),
        ),
        "graph_ca": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            ("ca_policies", "break_glass_principal_ids"),
        ),
        "graph_domains": (
            Backend.GRAPH,
            ("Domain.Read.All", "Directory.Read.All"),
            ("domains",),
        ),
        "graph_guests": (
            Backend.GRAPH,
            ("Policy.Read.All", "User.Read.All"),
            ("guests_bundle", "approved_guest_domains", "authorization_policy"),
        ),
        "graph_identity_protection": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            ("ca_policies", "break_glass_principal_ids"),
        ),
        "graph_mdo": (Backend.NOOP, (), ("secure_score_controls",)),
        "graph_pim": (
            Backend.GRAPH,
            ("RoleManagement.Read.Directory",),
            ("role_assignments", "role_eligibilities"),
        ),
        "graph_pim_policies": (
            Backend.GRAPH,
            ("RoleManagement.Read.Directory",),
            ("pim_policies_bundle",),
        ),
        "graph_security_defaults": (
            Backend.GRAPH,
            ("Policy.Read.All",),
            ("security_defaults_policy",),
        ),
        "graph_signins_roles": (
            Backend.GRAPH,
            (
                "Directory.Read.All",
                "AuditLog.Read.All",
                "RoleManagement.Read.Directory",
            ),
            ("role_assignments", "recent_signin_user_ids", "principal_directory"),
        ),
        "manual_identity": (Backend.NOOP, (), ("break_glass_principal_ids",)),
        "mde_onboarding": (Backend.MDE, (), ("mde_summary",)),
        "intune_collector": (
            Backend.GRAPH,
            ("DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All"),
            ("intune_bundle",),
        ),
        "mde_health_collector": (Backend.MDE, (), ("mde_health",)),
        "security_alerts_collector": (
            Backend.GRAPH,
            ("SecurityIncident.Read.All", "SecurityAlert.Read.All"),
            ("security_alerts_bundle",),
        ),
        "mdi_sensors": (
            Backend.PROXY,
            ("SecurityEvents.Read.All",),
            ("secure_score_controls",),
        ),
        "purview_dlp_collector": (
            Backend.PROXY,
            ("SecurityEvents.Read.All",),
            ("purview_dlp",),
        ),
        "sentinel_analytics": (Backend.ARM, (), ("sentinel_rules",)),
        "sentinel_ueba_collector": (Backend.ARM, (), ("sentinel_ueba",)),
        "sentinel_data_connectors_collector": (
            Backend.ARM,
            (),
            ("sentinel_data_connectors",),
        ),
        "sentinel_automation_rules_collector": (
            Backend.ARM,
            (),
            ("sentinel_automation_rules",),
        ),
        "sentinel_workspace_collector": (Backend.ARM, (), ("sentinel_workspace",)),
        "defender_pricings_collector": (
            Backend.ARM,
            (),
            ("defender_for_cloud_pricings",),
        ),
        "exchange_collector": (
            Backend.NOOP,
            (),
            ("exchange_bundle", "dns_records"),
        ),
        "collaboration_collector": (
            Backend.NOOP,
            (),
            ("collaboration_bundle",),
        ),
        "power_data_collector": (
            Backend.NOOP,
            (),
            ("power_data_bundle",),
        ),
    }
)

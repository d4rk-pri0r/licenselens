"""Intune / security / MDE / selective ARM operation catalog."""

from __future__ import annotations

from licenselens.collectors.contracts import CloudEnvironment
from licenselens.graph_ops_types import ApiFamily, GraphOperation

_CG = (CloudEnvironment.PUBLIC, CloudEnvironment.US_GOV)


def endpoint_operations() -> tuple[GraphOperation, ...]:
    dmg_cfg = ("DeviceManagementConfiguration.Read.All",)
    dmg_dev = ("DeviceManagementManagedDevices.Read.All",)
    machine = ("Machine.Read.All",)

    def op(
        operation_id: str,
        path: str,
        evidence_key: str,
        app: tuple[str, ...],
        delegated: tuple[str, ...],
        *,
        family: ApiFamily = ApiFamily.GRAPH,
        is_collection: bool = True,
        max_pages: int = 30,
        clouds: tuple[CloudEnvironment, ...] = _CG,
        description: str = "",
    ) -> GraphOperation:
        return GraphOperation(
            operation_id=operation_id,
            family=family,
            path=path,
            evidence_key=evidence_key,
            application_permissions=app,
            delegated_permissions=delegated,
            supported_clouds=clouds,
            is_collection=is_collection,
            max_pages=max_pages,
            description=description,
        )

    return (
        op(
            "intune_compliance_policies",
            "/deviceManagement/deviceCompliancePolicies",
            "graph.intune_compliance_policies",
            dmg_cfg,
            dmg_cfg,
            description="Intune device compliance policies",
        ),
        op(
            "intune_configuration_profiles",
            "/deviceManagement/deviceConfigurations",
            "graph.intune_configuration_profiles",
            dmg_cfg,
            dmg_cfg,
            description="Intune device configuration profiles",
        ),
        op(
            "intune_configuration_policies",
            "/deviceManagement/configurationPolicies",
            "graph.intune_configuration_policies",
            dmg_cfg,
            dmg_cfg,
            description="Intune settings-catalog configuration policies",
        ),
        op(
            "intune_managed_devices",
            "/deviceManagement/managedDevices",
            "graph.intune_managed_devices",
            dmg_dev,
            dmg_dev,
            max_pages=20,
            description="Intune managed device inventory (bounded)",
        ),
        op(
            "intune_atp_onboarding_state",
            "/deviceManagement/advancedThreatProtectionOnboardingStateSummary",
            "graph.intune_atp_onboarding_state",
            dmg_cfg,
            dmg_cfg,
            is_collection=False,
            description="Intune-MDE connector onboarding summary",
        ),
        op(
            "security_incidents",
            "/security/incidents",
            "graph.security_incidents",
            ("SecurityIncident.Read.All",),
            ("SecurityIncident.Read.All",),
            max_pages=10,
            description="Defender XDR incidents (capability operation signal)",
        ),
        op(
            "security_alerts_v2",
            "/security/alerts_v2",
            "graph.security_alerts",
            ("SecurityAlert.Read.All",),
            ("SecurityAlert.Read.All",),
            max_pages=10,
            description="Defender XDR alerts_v2 (capability operation signal)",
        ),
        op(
            "mde_machines",
            "/machines",
            "mde.machines",
            machine,
            machine,
            family=ApiFamily.MDE,
            max_pages=10,
            description="MDE onboarded machines",
        ),
        op(
            "mde_machine_health",
            "/machines",
            "mde.machine_health",
            machine,
            machine,
            family=ApiFamily.MDE,
            max_pages=10,
            description="MDE machine healthStatus summary",
        ),
        op(
            "arm_sentinel_alert_rules",
            "{workspace}/providers/Microsoft.SecurityInsights/alertRules",
            "arm.sentinel_alert_rules",
            (),
            (),
            family=ApiFamily.ARM,
            max_pages=40,
            description="Sentinel analytics rules (workspace-scoped)",
        ),
        op(
            "arm_sentinel_settings",
            "{workspace}/providers/Microsoft.SecurityInsights/settings",
            "arm.sentinel_settings",
            (),
            (),
            family=ApiFamily.ARM,
            max_pages=10,
            description="Sentinel settings including UEBA",
        ),
        op(
            "arm_defender_for_cloud_pricings",
            "subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings",
            "arm.defender_for_cloud_pricings",
            (),
            (),
            family=ApiFamily.ARM,
            max_pages=5,
            description="Defender for Cloud plan pricing (selective only)",
        ),
    )

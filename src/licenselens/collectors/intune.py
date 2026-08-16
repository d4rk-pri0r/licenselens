"""Collect Intune compliance, configuration, and managed-device signals."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.contracts import EvidenceEnvelope
from licenselens.collectors.graph_collect import SupportsGraphReads, collect_graph_operation
from licenselens.graph import GraphClient

__all__ = [
    "DEMO_INTUNE_BUNDLE",
    "collect_intune_asr_policies",
    "collect_intune_bundle",
    "collect_intune_compliance_policies",
    "collect_intune_compliance_state_summary",
    "collect_intune_configuration_policies",
    "collect_intune_configuration_profiles",
    "collect_intune_evidence",
    "collect_intune_mam_app_protections",
    "collect_intune_managed_devices",
]


def collect_intune_compliance_policies(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list("/deviceManagement/deviceCompliancePolicies", max_pages=30)


def collect_intune_configuration_profiles(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list("/deviceManagement/deviceConfigurations", max_pages=30)


def collect_intune_configuration_policies(client: GraphClient) -> list[dict[str, Any]]:
    """Settings catalog / endpoint-security style configuration policies."""
    return client.get_list("/deviceManagement/configurationPolicies", max_pages=30)


def collect_intune_managed_devices(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/deviceManagement/managedDevices",
        params={"$select": "id,deviceName,complianceState,operatingSystem,managementAgent"},
        max_pages=20,
    )


def collect_intune_asr_policies(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list(
        "/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies", max_pages=30
    )


def collect_intune_compliance_state_summary(client: GraphClient) -> dict[str, Any]:
    return client.get("/deviceManagement/deviceCompliancePolicyDeviceStateSummary")


def collect_intune_mam_app_protections(client: GraphClient) -> list[dict[str, Any]]:
    return client.get_list("/deviceAppManagement/managedAppProtections", max_pages=30)


def collect_intune_evidence(client: SupportsGraphReads) -> dict[str, EvidenceEnvelope]:
    return {
        "intune_compliance_policies": collect_graph_operation(client, "intune_compliance_policies"),
        "intune_configuration_profiles": collect_graph_operation(
            client, "intune_configuration_profiles"
        ),
        "intune_configuration_policies": collect_graph_operation(
            client, "intune_configuration_policies"
        ),
        "intune_managed_devices": collect_graph_operation(client, "intune_managed_devices"),
        "intune_asr_policies": collect_graph_operation(client, "intune_asr_policies"),
        "intune_device_state_summary": collect_graph_operation(
            client, "intune_device_state_summary"
        ),
        "intune_mam_app_protections": collect_graph_operation(
            client, "intune_mam_app_protections"
        ),
    }


def collect_intune_bundle(client: GraphClient) -> dict[str, Any]:
    return {
        "compliance_policies": collect_intune_compliance_policies(client),
        "configuration_profiles": collect_intune_configuration_profiles(client),
        "configuration_policies": collect_intune_configuration_policies(client),
        "managed_devices": collect_intune_managed_devices(client),
        "asr_policies": collect_intune_asr_policies(client),
        "compliance_state_summary": collect_intune_compliance_state_summary(client),
        "mam_app_protections": collect_intune_mam_app_protections(client),
    }


DEMO_INTUNE_BUNDLE: dict[str, Any] = {
    "compliance_policies": [
        {"id": "comp-1", "displayName": "Windows compliance baseline", "platforms": "windows10"}
    ],
    "configuration_profiles": [
        {
            "id": "cfg-1",
            "displayName": "BitLocker baseline",
            "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
        }
    ],
    "configuration_policies": [
        {
            "id": "ep-1",
            "name": "Endpoint security - Antivirus",
            "technologies": "mdm,microsoftSense",
            "templateReference": {"templateFamily": "endpointSecurityAntivirus"},
        }
    ],
    "managed_devices": [
        {
            "id": "dev-1",
            "deviceName": "LAPTOP-1",
            "complianceState": "compliant",
            "operatingSystem": "Windows",
        }
    ],
    "asr_policies": [
        {"id": "asr-1", "displayName": "Endpoint security - ASR rules"}
    ],
    "compliance_state_summary": {
        "compliantDeviceCount": 90,
        "nonCompliantDeviceCount": 0,
        "unknownDeviceCount": 0,
    },
    "mam_app_protections": [
        {
            "id": "mam-1",
            "displayName": "iOS app protection",
            "@odata.type": "#microsoft.graph.iosManagedAppProtection",
        }
    ],
}

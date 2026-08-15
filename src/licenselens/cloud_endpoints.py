"""Sovereign-cloud base URLs and token audiences for Graph, ARM, and MDE."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from licenselens.collectors.contracts import CloudEnvironment

__all__ = [
    "CloudEndpoints",
    "UnsupportedCloudError",
    "endpoints_for",
    "graph_base_url",
    "supported_clouds",
]


@dataclass(frozen=True, slots=True)
class UnsupportedCloudError(Exception):
    cloud: CloudEnvironment
    service: str

    def __str__(self) -> str:
        return f"{self.service} is not supported in cloud {self.cloud.value}"


@dataclass(frozen=True, slots=True)
class CloudEndpoints:
    """Resolved service roots for one national cloud."""

    cloud: CloudEnvironment
    graph_resource: str
    arm_resource: str
    mde_resource: str
    mde_supported: bool = True

    @property
    def graph_scope(self) -> str:
        return f"{self.graph_resource}/.default"

    @property
    def arm_scope(self) -> str:
        return f"{self.arm_resource}/.default"

    @property
    def mde_scope(self) -> str:
        return f"{self.mde_resource}/.default"

    def graph_base(self, *, api_version: str = "v1.0") -> str:
        version = api_version.strip().strip("/")
        return f"{self.graph_resource}/{version}"

    @property
    def mde_base(self) -> str:
        return f"{self.mde_resource}/api"


_ENDPOINTS: Final[Mapping[CloudEnvironment, CloudEndpoints]] = {
    CloudEnvironment.PUBLIC: CloudEndpoints(
        cloud=CloudEnvironment.PUBLIC,
        graph_resource="https://graph.microsoft.com",
        arm_resource="https://management.azure.com",
        mde_resource="https://api.securitycenter.microsoft.com",
    ),
    CloudEnvironment.US_GOV: CloudEndpoints(
        cloud=CloudEnvironment.US_GOV,
        graph_resource="https://graph.microsoft.us",
        arm_resource="https://management.usgovcloudapi.net",
        mde_resource="https://api-gov.securitycenter.microsoft.us",
    ),
    CloudEnvironment.CHINA: CloudEndpoints(
        cloud=CloudEnvironment.CHINA,
        graph_resource="https://microsoftgraph.chinacloudapi.cn",
        arm_resource="https://management.chinacloudapi.cn",
        mde_resource="https://api.securitycenter.microsoft.com",
        mde_supported=False,
    ),
}


def supported_clouds() -> tuple[CloudEnvironment, ...]:
    return tuple(_ENDPOINTS.keys())


def endpoints_for(cloud: CloudEnvironment) -> CloudEndpoints:
    try:
        return _ENDPOINTS[cloud]
    except KeyError as exc:
        raise UnsupportedCloudError(cloud=cloud, service="cloud_endpoints") from exc


def graph_base_url(cloud: CloudEnvironment, *, api_version: str = "v1.0") -> str:
    return endpoints_for(cloud).graph_base(api_version=api_version)

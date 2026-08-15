"""Types for the Graph/REST operation matrix."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from licenselens.collectors.contracts import CloudEnvironment


class ApiFamily(StrEnum):
    GRAPH = "graph"
    MDE = "mde"
    ARM = "arm"


@dataclass(frozen=True, slots=True)
class WritePermissionError(Exception):
    permission: str

    def __str__(self) -> str:
        return f"write permission not allowed: {self.permission}"


@dataclass(frozen=True, slots=True)
class PreviewApiVersionError(Exception):
    operation_id: str

    def __str__(self) -> str:
        return f"operation {self.operation_id} uses beta without preview=True"


@dataclass(frozen=True, slots=True)
class GraphOperation:
    """One read-only REST operation with least-privilege declarations."""

    operation_id: str
    family: ApiFamily
    path: str
    evidence_key: str
    application_permissions: tuple[str, ...]
    delegated_permissions: tuple[str, ...]
    supported_clouds: tuple[CloudEnvironment, ...] = (
        CloudEnvironment.PUBLIC,
        CloudEnvironment.US_GOV,
        CloudEnvironment.CHINA,
    )
    method: str = "GET"
    api_version: str = "v1.0"
    is_collection: bool = True
    max_pages: int = 30
    preview: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        for permission in (*self.application_permissions, *self.delegated_permissions):
            reject_write_permission(permission)
        if self.preview and self.api_version != "beta":
            object.__setattr__(self, "api_version", "beta")
        if not self.preview and self.api_version == "beta":
            raise PreviewApiVersionError(self.operation_id)


def reject_write_permission(permission: str) -> None:
    lowered = permission.lower()
    if "readwrite" in lowered or lowered.endswith(".write"):
        raise WritePermissionError(permission)
    if ".write." in lowered or lowered.endswith(".readwrite"):
        raise WritePermissionError(permission)

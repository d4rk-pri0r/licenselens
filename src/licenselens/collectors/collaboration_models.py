"""Typed models for Teams and SharePoint/OneDrive adapter payloads."""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from licenselens.collectors.exchange_models import PolicyItem, PolicyKind, SurfaceStatus
from licenselens.schema_contracts import JsonValue

COLLABORATION_ADAPTERS: Final[tuple[str, ...]] = (
    "spo_tenant",
    "teams_meeting",
    "teams_federation",
    "teams_client",
    "teams_apps",
)

SPO_ADAPTER: Final = "spo_tenant"
TEAMS_MEETING_ADAPTER: Final = "teams_meeting"
TEAMS_FEDERATION_ADAPTER: Final = "teams_federation"
TEAMS_CLIENT_ADAPTER: Final = "teams_client"
TEAMS_APPS_ADAPTER: Final = "teams_apps"

# SCuBA collaboration policy IDs (pinned scuba-2026-08.yaml) -> primary surface keys.
COVERAGE_SURFACE_MAP: Final[dict[str, tuple[str, str]]] = {
    "MS.SHAREPOINT.1.1v1": (SPO_ADAPTER, "sharing_capability"),
    "MS.SHAREPOINT.1.2v1": (SPO_ADAPTER, "onedrive_sharing"),
    "MS.SHAREPOINT.1.3v1": (SPO_ADAPTER, "domain_restrictions"),
    "MS.SHAREPOINT.2.1v1": (SPO_ADAPTER, "default_link"),
    "MS.SHAREPOINT.2.2v1": (SPO_ADAPTER, "default_link"),
    "MS.SHAREPOINT.3.1v1": (SPO_ADAPTER, "anyone_link_expiration"),
    "MS.SHAREPOINT.3.2v1": (SPO_ADAPTER, "anyone_link_permissions"),
    "MS.SHAREPOINT.3.3v2": (SPO_ADAPTER, "reauth_days"),
    "MS.TEAMS.1.1v1": (TEAMS_MEETING_ADAPTER, "meeting_policies"),
    "MS.TEAMS.1.2v2": (TEAMS_MEETING_ADAPTER, "meeting_policies"),
    "MS.TEAMS.1.3v1": (TEAMS_MEETING_ADAPTER, "meeting_policies"),
    "MS.TEAMS.1.4v1": (TEAMS_MEETING_ADAPTER, "meeting_policies"),
    "MS.TEAMS.1.5v1": (TEAMS_MEETING_ADAPTER, "meeting_policies"),
    "MS.TEAMS.1.6v1": (TEAMS_MEETING_ADAPTER, "meeting_policies"),
    "MS.TEAMS.1.7v2": (TEAMS_MEETING_ADAPTER, "broadcast_policies"),
    "MS.TEAMS.2.1v2": (TEAMS_FEDERATION_ADAPTER, "federation"),
    "MS.TEAMS.2.2v2": (TEAMS_FEDERATION_ADAPTER, "unmanaged_users"),
    "MS.TEAMS.2.3v2": (TEAMS_FEDERATION_ADAPTER, "unmanaged_users"),
    "MS.TEAMS.4.1v1": (TEAMS_CLIENT_ADAPTER, "email_integration"),
    "MS.TEAMS.5.1v2": (TEAMS_APPS_ADAPTER, "app_permission_policies"),
    "MS.TEAMS.5.2v2": (TEAMS_APPS_ADAPTER, "app_permission_policies"),
    "MS.TEAMS.5.3v2": (TEAMS_APPS_ADAPTER, "app_permission_policies"),
}

# Surfaces unavailable or limited on national clouds (GCC / GCCH / DoD).
NATIONAL_CLOUD_LIMITED_SURFACES: Final[frozenset[str]] = frozenset(
    {
        "unmanaged_users",
        "email_integration",
        "app_settings_v2",
    }
)


class CollaborationSurface(BaseModel):
    """One collection surface with explicit status (partial access safe)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    surface: str
    status: SurfaceStatus
    reason: str = ""
    items: list[PolicyItem] = Field(default_factory=list)
    raw_count: int = 0
    national_cloud_limited: bool = False


class CollaborationAdapterPayload(BaseModel):
    """Normalized payload for one allowlisted collaboration adapter."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    adapter: str
    module: str = ""
    collection: str = ""
    surfaces: dict[str, CollaborationSurface] = Field(default_factory=dict)
    collected_at: str | None = None
    source: str = "powershell.bridge"
    proxy: bool = False


class CollaborationBundle(BaseModel):
    """Aggregated SharePoint/OneDrive + Teams collection for evaluators/runner."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    adapters: dict[str, CollaborationAdapterPayload] = Field(default_factory=dict)
    direct: bool = True
    proxy: bool = False
    source: str = "powershell.collaboration"

    def surface(self, name: str) -> CollaborationSurface | None:
        for payload in self.adapters.values():
            found = payload.surfaces.get(name)
            if found is not None:
                return found
        return None

    def policies_for_surface(
        self,
        surface_name: str,
        *,
        kind: PolicyKind | None = None,
    ) -> list[PolicyItem]:
        """Return policy items for a surface; optional kind filter (global/custom)."""
        surface = self.surface(surface_name)
        if surface is None or surface.status is not SurfaceStatus.OK:
            return []
        if kind is None:
            return list(surface.items)
        return [item for item in surface.items if item.kind is kind]

    def custom_policies_visible(self, surface_name: str) -> bool:
        """True when custom policies are present even if a global/default is compliant."""
        surface = self.surface(surface_name)
        if surface is None or surface.status is not SurfaceStatus.OK:
            return False
        has_global = any(
            item.kind in {PolicyKind.DEFAULT, PolicyKind.EFFECTIVE} for item in surface.items
        )
        has_custom = any(item.kind is PolicyKind.CUSTOM for item in surface.items)
        if not has_custom:
            return True
        return has_global and has_custom

    def coverage_row_state(self, policy_id: str) -> tuple[SurfaceStatus, str]:
        """Map a SCuBA collaboration policy_id to evidence status + reason."""
        mapping = COVERAGE_SURFACE_MAP.get(policy_id)
        if mapping is None:
            return SurfaceStatus.UNSUPPORTED, f"unknown collaboration policy_id: {policy_id}"
        adapter_name, surface_name = mapping
        payload = self.adapters.get(adapter_name)
        if payload is None:
            return SurfaceStatus.UNAVAILABLE, f"adapter not collected: {adapter_name}"
        surface = payload.surfaces.get(surface_name)
        if surface is None:
            # App v2 settings may be the preferred path for TEAMS.5.* when present.
            if adapter_name == TEAMS_APPS_ADAPTER:
                v2 = payload.surfaces.get("app_settings_v2")
                if v2 is not None:
                    return v2.status, v2.reason or "app_settings_v2"
            return SurfaceStatus.UNAVAILABLE, f"surface missing: {surface_name}"
        if surface.status is SurfaceStatus.OK and surface.raw_count == 0:
            return SurfaceStatus.UNSUPPORTED, surface.reason or "empty surface"
        return surface.status, surface.reason


class CoverageRowEvidence(BaseModel):
    """Explicit evidence or unsupported/manual state for one coverage row."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    policy_id: str
    status: SurfaceStatus
    reason: str = ""
    adapter: str = ""
    surface: str = ""
    properties: dict[str, JsonValue] = Field(default_factory=dict)


__all__ = [
    "COLLABORATION_ADAPTERS",
    "COVERAGE_SURFACE_MAP",
    "NATIONAL_CLOUD_LIMITED_SURFACES",
    "SPO_ADAPTER",
    "TEAMS_APPS_ADAPTER",
    "TEAMS_CLIENT_ADAPTER",
    "TEAMS_FEDERATION_ADAPTER",
    "TEAMS_MEETING_ADAPTER",
    "CollaborationAdapterPayload",
    "CollaborationBundle",
    "CollaborationSurface",
    "CoverageRowEvidence",
    "PolicyItem",
    "PolicyKind",
    "SurfaceStatus",
]

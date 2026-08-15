"""Typed models for Power Platform, Power BI, and Purview adapter payloads."""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from licenselens.collectors.exchange_models import PolicyItem, PolicyKind, SurfaceStatus
from licenselens.schema_contracts import JsonValue

POWER_DATA_ADAPTERS: Final[tuple[str, ...]] = (
    "pp_tenant",
    "pp_environments",
    "pp_dlp",
    "pp_isolation",
    "pbi_tenant",
    "purview_governance",
)

PP_TENANT_ADAPTER: Final = "pp_tenant"
PP_ENVIRONMENTS_ADAPTER: Final = "pp_environments"
PP_DLP_ADAPTER: Final = "pp_dlp"
PP_ISOLATION_ADAPTER: Final = "pp_isolation"
PBI_TENANT_ADAPTER: Final = "pbi_tenant"
PURVIEW_ADAPTER: Final = "purview_governance"

# SCuBA Power Platform / Power BI policy IDs -> (adapter, surface).
# Manual/portal-only rows map to explicit unsupported surfaces on pp_tenant.
COVERAGE_SURFACE_MAP: Final[dict[str, tuple[str, str]]] = {
    "MS.POWERPLATFORM.1.1v1": (PP_TENANT_ADAPTER, "environment_creation"),
    "MS.POWERPLATFORM.1.2v1": (PP_TENANT_ADAPTER, "environment_creation"),
    "MS.POWERPLATFORM.2.1v1": (PP_DLP_ADAPTER, "dlp_policies"),
    "MS.POWERPLATFORM.2.2v1": (PP_DLP_ADAPTER, "dlp_policies"),
    "MS.POWERPLATFORM.3.1v1": (PP_ISOLATION_ADAPTER, "tenant_isolation"),
    "MS.POWERPLATFORM.3.2v1": (PP_TENANT_ADAPTER, "isolation_allowlist"),
    "MS.POWERPLATFORM.4.1v1": (PP_TENANT_ADAPTER, "content_security_policy"),
    "MS.POWERPLATFORM.5.1v1": (PP_TENANT_ADAPTER, "power_pages"),
    "MS.POWERPLATFORM.6.1v1": (PP_TENANT_ADAPTER, "share_with_everyone"),
    "MS.POWERBI.1.1v1": (PBI_TENANT_ADAPTER, "publish_to_web"),
    "MS.POWERBI.2.1v1": (PBI_TENANT_ADAPTER, "guest_access"),
    "MS.POWERBI.3.1v1": (PBI_TENANT_ADAPTER, "external_invite"),
    "MS.POWERBI.4.1v1": (PBI_TENANT_ADAPTER, "service_principal_api"),
    "MS.POWERBI.4.2v1": (PBI_TENANT_ADAPTER, "service_principal_profiles"),
    "MS.POWERBI.5.1v1": (PBI_TENANT_ADAPTER, "resource_key_auth"),
    "MS.POWERBI.6.1v1": (PBI_TENANT_ADAPTER, "python_r_visuals"),
    "MS.POWERBI.7.1v1": (PBI_TENANT_ADAPTER, "sensitivity_labels"),
}

# Purview surfaces collected for direct evidence (not SCuBA power rows).
PURVIEW_SURFACES: Final[tuple[str, ...]] = (
    "dlp_policies",
    "dlp_rules",
    "sensitivity_labels",
    "label_policies",
    "retention_policies",
    "retention_rules",
    "audit_config",
)

MANUAL_PORTAL_POLICY_IDS: Final[frozenset[str]] = frozenset(
    {
        "MS.POWERPLATFORM.3.2v1",
        "MS.POWERPLATFORM.4.1v1",
    }
)


class PowerDataSurface(BaseModel):
    """One collection surface with explicit status (partial access safe)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    surface: str
    status: SurfaceStatus
    reason: str = ""
    items: list[PolicyItem] = Field(default_factory=list)
    raw_count: int = 0
    portal_only: bool = False


class PowerDataAdapterPayload(BaseModel):
    """Normalized payload for one allowlisted power-data adapter."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    adapter: str
    module: str = ""
    collection: str = ""
    surfaces: dict[str, PowerDataSurface] = Field(default_factory=dict)
    collected_at: str | None = None
    source: str = "powershell.bridge"
    proxy: bool = False


class PowerDataBundle(BaseModel):
    """Aggregated Power Platform + Power BI + Purview collection."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    adapters: dict[str, PowerDataAdapterPayload] = Field(default_factory=dict)
    direct: bool = True
    proxy: bool = False
    source: str = "powershell.power_data"

    def surface(self, name: str) -> PowerDataSurface | None:
        for payload in self.adapters.values():
            found = payload.surfaces.get(name)
            if found is not None:
                return found
        return None

    def coverage_row_state(self, policy_id: str) -> tuple[SurfaceStatus, str]:
        """Map a SCuBA power policy_id to evidence status + reason."""
        mapping = COVERAGE_SURFACE_MAP.get(policy_id)
        if mapping is None:
            return SurfaceStatus.UNSUPPORTED, f"unknown power-data policy_id: {policy_id}"
        adapter_name, surface_name = mapping
        payload = self.adapters.get(adapter_name)
        if payload is None:
            return SurfaceStatus.UNAVAILABLE, f"adapter not collected: {adapter_name}"
        surface = payload.surfaces.get(surface_name)
        if surface is None:
            return SurfaceStatus.UNAVAILABLE, f"surface missing: {surface_name}"
        if policy_id in MANUAL_PORTAL_POLICY_IDS:
            # Prefer explicit portal-only/manual even if fixture marks unsupported.
            if surface.status is SurfaceStatus.OK:
                return surface.status, surface.reason
            return (
                SurfaceStatus.UNSUPPORTED,
                surface.reason or "manual/portal-only",
            )
        # Distinguish absent (ok + empty) from unreadable (denied/unavailable).
        if surface.status is SurfaceStatus.OK and surface.raw_count == 0:
            if surface.reason.startswith("absent"):
                return SurfaceStatus.OK, surface.reason
            return SurfaceStatus.OK, surface.reason or "empty surface (absent configuration)"
        return surface.status, surface.reason


class CoverageRowEvidence(BaseModel):
    """Explicit evidence or unsupported/manual state for one coverage row."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    policy_id: str
    status: SurfaceStatus
    reason: str = ""
    adapter: str = ""
    surface: str = ""
    portal_only: bool = False
    properties: dict[str, JsonValue] = Field(default_factory=dict)


__all__ = [
    "COVERAGE_SURFACE_MAP",
    "MANUAL_PORTAL_POLICY_IDS",
    "PBI_TENANT_ADAPTER",
    "POWER_DATA_ADAPTERS",
    "PP_DLP_ADAPTER",
    "PP_ENVIRONMENTS_ADAPTER",
    "PP_ISOLATION_ADAPTER",
    "PP_TENANT_ADAPTER",
    "PURVIEW_ADAPTER",
    "PURVIEW_SURFACES",
    "CoverageRowEvidence",
    "PolicyItem",
    "PolicyKind",
    "PowerDataAdapterPayload",
    "PowerDataBundle",
    "PowerDataSurface",
    "SurfaceStatus",
]

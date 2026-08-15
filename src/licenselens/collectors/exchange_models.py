"""Typed models for Exchange Online and Security/Compliance adapter payloads."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from licenselens.schema_contracts import JsonValue

EXCHANGE_ADAPTERS: Final[tuple[str, ...]] = (
    "exo_audit",
    "exo_remote_domains",
    "exo_transport",
    "exo_smtp_auth",
    "exo_sharing",
    "exo_accepted_domains",
    "exo_dkim",
    "exo_threat_policies",
    "scc_compliance",
)

THREAT_ADAPTER: Final = "exo_threat_policies"
AUDIT_ADAPTER: Final = "exo_audit"
COMPLIANCE_ADAPTER: Final = "scc_compliance"


class PolicyKind(StrEnum):
    DEFAULT = "default"
    CUSTOM = "custom"
    PRESET_STANDARD = "preset_standard"
    PRESET_STRICT = "preset_strict"
    EFFECTIVE = "effective"


class SurfaceStatus(StrEnum):
    OK = "ok"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    DISCONNECTED = "disconnected"


class PolicyItem(BaseModel):
    """One policy, rule, or effective configuration row."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    name: str
    identity: str | None = None
    kind: PolicyKind = PolicyKind.CUSTOM
    enabled: bool | None = None
    properties: dict[str, JsonValue] = Field(default_factory=dict)
    assignments: list[str] = Field(default_factory=list)


class ExchangeSurface(BaseModel):
    """One collection surface with explicit status (partial access safe)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    surface: str
    status: SurfaceStatus
    reason: str = ""
    items: list[PolicyItem] = Field(default_factory=list)
    raw_count: int = 0


class ExchangeAdapterPayload(BaseModel):
    """Normalized payload for one allowlisted Exchange/SCC adapter."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    adapter: str
    module: str = ""
    collection: str = ""
    surfaces: dict[str, ExchangeSurface] = Field(default_factory=dict)
    collected_at: str | None = None
    source: str = "powershell.bridge"
    proxy: bool = False


class ExchangeBundle(BaseModel):
    """Aggregated Exchange + SCC collection for evaluators/runner."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    adapters: dict[str, ExchangeAdapterPayload] = Field(default_factory=dict)
    direct: bool = True
    proxy: bool = False
    source: str = "powershell.exchange"

    def surface(self, name: str) -> ExchangeSurface | None:
        for payload in self.adapters.values():
            found = payload.surfaces.get(name)
            if found is not None:
                return found
        return None

    def has_usable_threat_policies(self) -> bool:
        """True when Safe Links/Attachments/preset were read directly."""
        threat = self.adapters.get(THREAT_ADAPTER)
        if threat is None:
            return False
        required = ("safe_links", "safe_attachments", "preset_security")
        for key in required:
            surface = threat.surfaces.get(key)
            if surface is None or surface.status is not SurfaceStatus.OK:
                return False
        return True

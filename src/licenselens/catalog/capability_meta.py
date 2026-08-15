"""Capability catalog metadata enums and load-time diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class EntitlementKind(StrEnum):
    """How a capability is typically licensed relative to a suite."""

    INCLUDED = "included"
    BASE = "base"
    ADD_ON = "add_on"
    CONSUMPTION = "consumption"


class CatalogCloud(StrEnum):
    """Clouds where a catalog entry is known to apply."""

    COMMERCIAL = "commercial"
    GCC = "gcc"
    GCC_HIGH = "gcc_high"
    DOD = "dod"


class CapabilityBackend(StrEnum):
    """Evidence backends a capability's checks are expected to use."""

    GRAPH = "graph"
    EXCHANGE_POWERSHELL = "exchange_powershell"
    TEAMS_POWERSHELL = "teams_powershell"
    SHAREPOINT_POWERSHELL = "sharepoint_powershell"
    SECURITY_COMPLIANCE_POWERSHELL = "security_compliance_powershell"
    POWER_PLATFORM = "power_platform"
    POWER_BI = "power_bi"
    MDE = "mde"
    ARM = "arm"
    MANUAL = "manual"


ALL_CATALOG_CLOUDS: Final[tuple[CatalogCloud, ...]] = (
    CatalogCloud.COMMERCIAL,
    CatalogCloud.GCC,
    CatalogCloud.GCC_HIGH,
    CatalogCloud.DOD,
)


@dataclass(frozen=True, slots=True)
class CatalogLoadError(Exception):
    """Typed failure while parsing or validating the capability catalog."""

    diagnostics: tuple[str, ...]

    def __str__(self) -> str:
        return "capability catalog error: " + ", ".join(self.diagnostics)

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class SupportState(StrEnum):
    DIRECT = "direct"
    PROXY = "proxy"
    MANUAL = "manual"
    UNSUPPORTED = "unsupported"
    DIRECT_WITH_PROXY_FALLBACK = "direct_with_proxy_fallback"


class CoverageDisposition(StrEnum):
    IMPLEMENTED_DIRECT = "implemented_direct"
    IMPLEMENTED_PROXY = "implemented_proxy"
    MANUAL = "manual"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class ReferenceModelPaths:
    capabilities_path: Path
    checks_root: Path
    profiles_root: Path
    coverage_path: Path
    permission_docs_path: Path


@dataclass(frozen=True, slots=True)
class ReferenceCatalogError(Exception):
    diagnostics: tuple[str, ...]

    def __str__(self) -> str:
        return "reference catalog drift: " + ", ".join(self.diagnostics)


class StrictReferenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReferenceCapability(StrictReferenceModel):
    id: str
    workloads: tuple[str, ...]
    required_by_checks: tuple[str, ...]
    service_plan_names: tuple[str, ...]
    sku_part_numbers: tuple[str, ...]
    service_plan_aliases: tuple[str, ...]
    sku_aliases: tuple[str, ...]
    entitlement_kind: str
    clouds: tuple[str, ...]
    backends: tuple[str, ...]
    source_version: str
    docs_url: str | None


class ReferenceCheck(StrictReferenceModel):
    id: str
    collector: str
    evidence_keys: tuple[str, ...]
    evaluator_registered: bool
    required_capabilities: tuple[str, ...]
    source_path: str
    support_state: SupportState


class ReferenceProfile(StrictReferenceModel):
    id: str
    packs: tuple[str, ...]
    check_ids: tuple[str, ...]
    resolved_check_ids: tuple[str, ...]


class ReferenceCoverageRow(StrictReferenceModel):
    policy_id: str
    product: str
    disposition: CoverageDisposition
    local_check_ids: tuple[str, ...]
    source_path: str


class ReferenceModel(StrictReferenceModel):
    capabilities: tuple[ReferenceCapability, ...]
    checks: tuple[ReferenceCheck, ...]
    profiles: tuple[ReferenceProfile, ...]
    graph_permissions: tuple[str, ...]
    permission_modules: tuple[str, ...]
    coverage_rows: tuple[ReferenceCoverageRow, ...]

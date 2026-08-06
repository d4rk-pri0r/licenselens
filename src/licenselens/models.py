"""Shared data models for entitlements, checks, and findings."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class FindingStatus(StrEnum):
    GAP = "gap"
    PARTIAL = "partial"
    OK = "ok"
    NOT_LICENSED = "not_licensed"
    ERROR = "error"
    SKIPPED = "skipped"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ValueImpact(StrEnum):
    """How much paid capability is left on the table if this check fails."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Workload(StrEnum):
    IDENTITY = "identity"
    DEFENDER = "defender"
    SENTINEL = "sentinel"
    PURVIEW = "purview"
    ENDPOINT = "endpoint"
    GENERAL = "general"


class ServicePlan(BaseModel):
    service_plan_id: str | None = None
    service_plan_name: str
    provisioning_status: str | None = None


class SubscribedSku(BaseModel):
    sku_id: str | None = None
    sku_part_number: str
    capability_status: str | None = None
    prepaid_units: int | None = None
    consumed_units: int | None = None
    service_plans: list[ServicePlan] = Field(default_factory=list)


class Capability(BaseModel):
    id: str
    name: str
    description: str = ""
    workloads: list[Workload] = Field(default_factory=list)
    service_plan_names: list[str] = Field(default_factory=list)
    sku_part_numbers: list[str] = Field(default_factory=list)
    docs_url: str | None = None


class CheckDefinition(BaseModel):
    id: str
    title: str
    description: str = ""
    workload: Workload = Workload.GENERAL
    required_capabilities: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    value_impact: ValueImpact = ValueImpact.MEDIUM
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    collector: str = "noop"
    enabled: bool = True
    # Path to the YAML file this was loaded from (set at load time)
    source_path: str | None = None


class Finding(BaseModel):
    check_id: str
    title: str
    workload: Workload
    status: FindingStatus
    severity: Severity
    value_impact: ValueImpact
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    entitlements_used: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    tool: str = "licenselens"
    version: str
    tenant_id: str | None = None
    scanned_at: str
    owned_capabilities: list[str] = Field(default_factory=list)
    subscribed_skus: list[SubscribedSku] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    @property
    def counts_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.status.value] = counts.get(f.status.value, 0) + 1
        return counts

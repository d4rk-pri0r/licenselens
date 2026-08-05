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


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


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


STATUS_PLAIN_LABELS: dict[str, str] = {
    "gap": "Needs attention",
    "partial": "Partly set up",
    "ok": "Looking good",
    "not_licensed": "Not in your plan",
    "skipped": "Check pending",
    "error": "Could not verify",
}

CONFIDENCE_PLAIN_LABELS: dict[str, str] = {
    "high": "High confidence",
    "medium": "Medium confidence",
    "low": "Low confidence — verify in portal",
}

PROXY_CHECK_IDS: frozenset[str] = frozenset(
    {
        "mdo-p2-policies-default",
        "mdi-sensors-missing",
        "pur-dlp-not-enforced",
    }
)

PROXY_VERIFY_NOTE = (
    "Based on Microsoft Secure Score signals — confirm the real setting in the "
    "Microsoft 365 / security admin portal before treating this as definitive."
)


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
    plain_name: str = ""
    outcome: str = ""
    why_it_matters: str = ""
    if_unused: str = ""
    workloads: list[Workload] = Field(default_factory=list)
    service_plan_names: list[str] = Field(default_factory=list)
    sku_part_numbers: list[str] = Field(default_factory=list)
    docs_url: str | None = None

    @property
    def display_plain_name(self) -> str:
        return self.plain_name or self.name


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
    customer_title: str = ""
    customer_summary: str = ""
    customer_next_step: str = ""
    source_path: str | None = None

    @property
    def display_customer_title(self) -> str:
        return self.customer_title or self.title


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
    customer_title: str = ""
    customer_summary: str = ""
    customer_next_step: str = ""
    status_label: str = ""
    confidence: Confidence = Confidence.MEDIUM
    confidence_label: str = ""
    data_sources: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def display_customer_title(self) -> str:
        return self.customer_title or self.title


class CapabilitySummary(BaseModel):
    id: str
    name: str
    plain_name: str
    outcome: str = ""
    why_it_matters: str = ""
    if_unused: str = ""
    docs_url: str | None = None


class ScanResult(BaseModel):
    tool: str = "security-license-lens"
    tool_display_name: str = "Security License Lens"
    version: str
    tenant_id: str | None = None
    tenant_display_name: str | None = None
    tenant_slug: str | None = None
    scan_mode: str = "dry_run"
    auth_mode: str | None = None
    scanned_at: str
    owned_capabilities: list[str] = Field(default_factory=list)
    capability_summaries: list[CapabilitySummary] = Field(default_factory=list)
    subscribed_skus: list[SubscribedSku] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    data_sources_used: list[str] = Field(default_factory=list)
    workspace_resource_id: str | None = None
    strict_proxy: bool = True

    @property
    def counts_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.status.value] = counts.get(f.status.value, 0) + 1
        return counts

    @property
    def counts_by_confidence(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.confidence.value if f.confidence else "medium"
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def has_actionable_gaps(self) -> bool:
        return any(f.status in {FindingStatus.GAP, FindingStatus.PARTIAL} for f in self.findings)

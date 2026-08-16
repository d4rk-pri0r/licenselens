"""Shared data models for entitlements, checks, and findings."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from licenselens.schema_contracts import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_MAJOR,
    AcceptedRiskAnnotation,
    CollectionSummary,
    EvaluationMode,
    ProfileId,
    SchemaVersion,
    SourceReference,
    UnsupportedSchemaVersionError,
)
from licenselens.schema_contracts import CollectionStatus as CollectionStatus


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


class Effort(StrEnum):
    """Rough time-to-fix bucket used for move effort labels (not a quote)."""

    MINUTES = "minutes"
    HOURS = "hours"
    HALF_DAY = "half_day"
    DAYS = "days"


class BlastRadius(StrEnum):
    """Who is affected if this protection stays off."""

    ADMIN = "admin"
    ALL_USERS = "all_users"
    DEVICES = "devices"
    DATA = "data"


class CheckPack(StrEnum):
    """Pack grouping used for ranking and the top card."""

    IDENTITY = "identity"
    EMAIL = "email"
    ENDPOINT = "endpoint"
    COLLABORATION = "collaboration"
    POWER_PLATFORM = "power-platform"
    POWER_BI = "power-bi"
    STARTER = "starter"


class ExposureClass(StrEnum):
    """Severity class beyond an ordinary gap (drives the EXPOSED chip)."""

    NONE = "none"
    ELEVATED = "elevated"
    EXPOSED = "exposed"


class Workload(StrEnum):
    IDENTITY = "identity"
    DEFENDER = "defender"
    SENTINEL = "sentinel"
    PURVIEW = "purview"
    ENDPOINT = "endpoint"
    EXCHANGE = "exchange"
    COLLABORATION = "collaboration"
    TEAMS = "teams"
    POWER_PLATFORM = "power_platform"
    POWER_BI = "power_bi"
    INTUNE = "intune"
    AZURE = "azure"
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

EFFORT_PLAIN_LABELS: dict[str, str] = {
    "minutes": "~minutes",
    "hours": "~a few hours",
    "half_day": "~half a day",
    "days": "~days",
}

EFFORT_DISCLAIMER = "Effort is a rough guide, not a quote."

PACK_PLAIN_LABELS: dict[str, str] = {
    "identity": "Identity",
    "email": "Email",
    "endpoint": "Endpoint",
    "collaboration": "Collaboration",
    "starter": "Starter",
}

IMPACT_PLAIN_LABELS: dict[str, str] = {
    "high": "High impact",
    "medium": "Medium impact",
    "low": "Low impact",
}

EXPOSURE_PLAIN_LABELS: dict[str, str] = {
    "exposed": "EXPOSED",
    "elevated": "ELEVATED",
    "none": "None",
}

# Top-card tagline.
TAGLINE = "Entitlements, controls, and configuration gaps."

# Capability rollup statuses shown on the top card.
CAPABILITY_STATUS_LABELS: dict[str, str] = {
    "fully_working": "Fully working",
    "needs_attention": "Needs attention",
    "partly_set_up": "Partly set up",
    "not_licensed": "Not in your plan",
}

# Default packs for ranking/rollup. Email is off by default (no Graph API for
# MDO policy config — Exchange Online PowerShell only).
DEFAULT_PACKS: list[str] = ["identity", "endpoint"]

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
    service_plan_ids: list[str] = Field(default_factory=list)
    sku_part_numbers: list[str] = Field(default_factory=list)
    service_plan_aliases: list[str] = Field(default_factory=list)
    sku_aliases: list[str] = Field(default_factory=list)
    entitlement_kind: str = "included"
    clouds: list[str] = Field(default_factory=list)
    backends: list[str] = Field(default_factory=list)
    source_version: str = ""
    docs_url: str | None = None

    @property
    def display_plain_name(self) -> str:
        return self.plain_name or self.name

    @property
    def matching_plan_names(self) -> frozenset[str]:
        return frozenset(
            name.upper() for name in (*self.service_plan_names, *self.service_plan_aliases)
        )

    @property
    def matching_service_plan_ids(self) -> frozenset[str]:
        return frozenset(guid.lower() for guid in self.service_plan_ids if guid)

    @property
    def matching_sku_part_numbers(self) -> frozenset[str]:
        return frozenset(name.upper() for name in (*self.sku_part_numbers, *self.sku_aliases))


class CheckDefinition(BaseModel):
    id: str
    title: str
    description: str = ""
    workload: Workload = Workload.GENERAL
    required_capabilities: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    value_impact: ValueImpact = ValueImpact.MEDIUM
    impact: ValueImpact = ValueImpact.MEDIUM
    effort: Effort = Effort.HOURS
    blast_radius: BlastRadius = BlastRadius.ALL_USERS
    pack: CheckPack = CheckPack.STARTER
    exposure_class: ExposureClass = ExposureClass.NONE
    deep_link: str | None = None
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    collector: str = "noop"
    enabled: bool = True
    customer_title: str = ""
    customer_summary: str = ""
    expected_state: str = ""
    customer_next_step: str = ""
    #: Check-specific "why it matters" sentence for the report D-slot. When
    #: absent the view model falls back to the matched capability's blurb.
    why_it_matters: str = ""
    source_path: str | None = None

    @property
    def display_customer_title(self) -> str:
        return self.customer_title or self.title

    @property
    def effort_label(self) -> str:
        return EFFORT_PLAIN_LABELS.get(self.effort.value, self.effort.value)

    @property
    def impact_label(self) -> str:
        return IMPACT_PLAIN_LABELS.get(self.impact.value, self.impact.value)

    @property
    def pack_label(self) -> str:
        return PACK_PLAIN_LABELS.get(self.pack.value, self.pack.value)


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)

    check_id: str
    title: str
    workload: Workload
    status: FindingStatus
    severity: Severity
    value_impact: ValueImpact
    impact: ValueImpact = ValueImpact.MEDIUM
    effort: Effort = Effort.HOURS
    blast_radius: BlastRadius = BlastRadius.ALL_USERS
    pack: CheckPack = CheckPack.STARTER
    exposure_class: ExposureClass = ExposureClass.NONE
    deep_link: str | None = None
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    entitlements_used: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    customer_title: str = ""
    customer_summary: str = ""
    customer_next_step: str = ""
    why_it_matters: str = Field(default="", exclude=True)  # render-only: keeps artifact shape
    status_label: str = ""
    confidence: Confidence = Confidence.MEDIUM
    confidence_label: str = ""
    data_sources: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    evaluation_mode: EvaluationMode = EvaluationMode.DIRECT
    source_references: list[SourceReference] = Field(default_factory=list)
    accepted_risks: list[AcceptedRiskAnnotation] = Field(default_factory=list)

    @model_validator(mode="after")
    def reject_indirect_high_confidence_ok(self) -> Self:
        if (
            self.evaluation_mode
            in {
                EvaluationMode.PROXY,
                EvaluationMode.MANUAL,
                EvaluationMode.UNSUPPORTED,
            }
            and self.status == FindingStatus.OK
            and self.confidence == Confidence.HIGH
        ):
            msg = "indirect evaluations cannot be high-confidence ok"
            raise ValueError(msg)
        return self

    @property
    def display_customer_title(self) -> str:
        return self.customer_title or self.title

    @property
    def effort_label(self) -> str:
        return EFFORT_PLAIN_LABELS.get(self.effort.value, self.effort.value)

    @property
    def impact_label(self) -> str:
        return IMPACT_PLAIN_LABELS.get(self.impact.value, self.impact.value)

    @property
    def pack_label(self) -> str:
        return PACK_PLAIN_LABELS.get(self.pack.value, self.pack.value)


class CapabilitySummary(BaseModel):
    id: str
    name: str
    plain_name: str
    matched_skus: list[str] = Field(default_factory=list)
    matched_service_plans: list[str] = Field(default_factory=list)
    outcome: str = ""
    why_it_matters: str = ""
    if_unused: str = ""
    docs_url: str | None = None


class TopMove(BaseModel):
    """One prioritized move for the top card (owner voice, ≤3 shown)."""

    title: str
    why: str
    effort: Effort = Effort.HOURS
    check_ids: list[str] = Field(default_factory=list)
    deep_link: str | None = None
    customer_next_step: str = ""

    @property
    def effort_label(self) -> str:
        return EFFORT_PLAIN_LABELS.get(self.effort.value, self.effort.value)


class CapabilityRollup(BaseModel):
    """Rolled-up status of owned, in-scope capabilities for the top card."""

    you_own: int = 0
    fully_working: int = 0
    needs_attention: int = 0
    partly_set_up: int = 0
    not_licensed: int = 0
    realized_percent: int = 0

    @property
    def realized_sentence(self) -> str:
        missing = self.you_own - self.fully_working
        if self.you_own <= 0:
            return "No assessed protections were owned."
        if missing <= 0:
            return f"All {self.you_own} assessed protections are fully working."
        return f"{missing} of {self.you_own} priority capabilities still need attention"


class CapabilityOutcome(BaseModel):
    """Per-capability rollup result shown with the top card numbers."""

    id: str
    name: str
    plain_name: str
    status: str
    status_label: str = ""
    related_check_ids: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: SchemaVersion = CURRENT_SCHEMA_VERSION
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
    profile_ids: list[ProfileId] = Field(default_factory=list)
    collection_summaries: list[CollectionSummary] = Field(default_factory=list)
    source_references: list[SourceReference] = Field(default_factory=list)
    accepted_risks: list[AcceptedRiskAnnotation] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    data_sources_used: list[str] = Field(default_factory=list)
    workspace_resource_id: str | None = None
    strict_proxy: bool = True
    packs_scanned: list[str] = Field(default_factory=list)
    moves: list[TopMove] = Field(default_factory=list)
    capability_rollup: CapabilityRollup = Field(default_factory=CapabilityRollup)
    capability_outcomes: list[CapabilityOutcome] = Field(default_factory=list)
    has_exposed: bool = False
    exposed_check_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def reject_unsupported_schema_version(self) -> Self:
        version = str(self.schema_version)
        major = version.split(".", maxsplit=1)[0]
        if major != SUPPORTED_SCHEMA_MAJOR:
            raise UnsupportedSchemaVersionError(schema_version=version)
        return self

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

    @property
    def display_scanned_at(self) -> str:
        try:
            from datetime import datetime

            dt = datetime.fromisoformat(self.scanned_at)
            return dt.strftime("%B %d, %Y at %I:%M %p UTC")
        except (ValueError, AttributeError):
            return self.scanned_at

    @property
    def exposed_count(self) -> int:
        return len(self.exposed_check_ids)

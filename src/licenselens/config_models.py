from __future__ import annotations

import json
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Self
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from licenselens.schema_contracts import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_MAJOR,
    AcceptedRiskId,
    JsonValue,
    ProfileId,
    SchemaVersion,
    UnsupportedSchemaVersionError,
)


class WaiverStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"


class BackendPreference(StrEnum):
    GRAPH = "graph"
    ARM = "arm"
    EXCHANGE_ONLINE = "exchange_online"
    DEFENDER = "defender"
    SECURE_SCORE = "secure_score"
    MANUAL = "manual"


class RuleSelector(StrEnum):
    FINDING_STATUS = "finding.status"
    FINDING_SEVERITY = "finding.severity"
    FINDING_PACK = "finding.pack"
    FINDING_WORKLOAD = "finding.workload"
    FINDING_CHECK_ID = "finding.check_id"
    FINDING_CONFIDENCE = "finding.confidence"
    FINDING_EVALUATION_MODE = "finding.evaluation_mode"
    FINDING_ENTITLEMENTS = "finding.entitlements_used"
    TENANT_DOMAINS = "tenant.domains"
    TENANT_SENSITIVE_USERS = "tenant.sensitive_users"
    COLLECTION_STATUS = "collection.status"


class RuleOperator(StrEnum):
    EQ = "eq"
    NE = "ne"
    IN = "in"
    NOT_IN = "not_in"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    EXISTS = "exists"


class CollectionComparator(StrEnum):
    ANY = "any"
    ALL = "all"
    COUNT = "count"


class StrictConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ThresholdSettings(StrictConfigModel):
    fail_at_or_above: int = Field(default=1, ge=0)
    warn_at_or_above: int = Field(default=1, ge=0)
    minimum_confidence: str = "medium"


class RedactionSettings(StrictConfigModel):
    enabled: bool = True
    redact_tenant_ids: bool = True
    redact_user_principals: bool = True
    redact_domains: bool = False
    replacement: str = "[redacted]"


class BackendPreferences(StrictConfigModel):
    preferred: list[BackendPreference] = Field(default_factory=lambda: [BackendPreference.GRAPH])
    allow_proxy: bool = False
    allow_manual: bool = True

    @field_validator("preferred")
    @classmethod
    def reject_duplicate_backends(cls, value: list[BackendPreference]) -> list[BackendPreference]:
        if len(value) != len(set(value)):
            msg = "duplicate backend preference"
            raise ValueError(msg)
        return value


class Exclusion(StrictConfigModel):
    id: str
    check_id: str
    reason: str = Field(min_length=1)
    owner: str
    expires_on: date | None = None
    principal_ids: list[str] = Field(default_factory=list)
    kind: str = "general"


class AcceptedRiskWaiver(StrictConfigModel):
    id: AcceptedRiskId
    check_id: str
    owner: str
    reason: str
    expires_on: date
    source: str = "profile"

    @computed_field
    @property
    def status(self) -> WaiverStatus:
        if self.expires_on < date.today():
            return WaiverStatus.EXPIRED
        return WaiverStatus.ACTIVE

    @computed_field
    @property
    def suppresses_finding(self) -> bool:
        return False


class CustomRuleCondition(StrictConfigModel):
    selector: RuleSelector
    operator: RuleOperator
    value: JsonValue = None
    collection: CollectionComparator | None = None


class CustomRule(StrictConfigModel):
    id: str
    title: str = ""
    selector: RuleSelector
    operator: RuleOperator
    value: JsonValue = None
    collection: CollectionComparator | None = None
    conditions: list[CustomRuleCondition] = Field(default_factory=list)
    description: str = ""
    rationale: str = ""
    references: list[str] = Field(default_factory=list)

    @field_validator("references")
    @classmethod
    def reject_unsafe_urls(cls, value: list[str]) -> list[str]:
        for url in value:
            parsed = urlparse(url)
            if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
                msg = "reference URLs must be absolute https URLs without credentials"
                raise ValueError(msg)
        return value


class AssessmentProfile(StrictConfigModel):
    schema_version: SchemaVersion = CURRENT_SCHEMA_VERSION
    id: ProfileId
    name: str
    description: str = ""
    packs: list[str] = Field(default_factory=list)
    check_ids: list[str] = Field(default_factory=list)
    thresholds: ThresholdSettings = Field(default_factory=ThresholdSettings)
    sensitive_users: list[str] = Field(default_factory=list)
    sensitive_domains: list[str] = Field(default_factory=list)
    allowed_forwarding_domains: list[str] = Field(default_factory=list)
    dmarc_agency_contact: str = ""
    dmarc_federal_contact: str = ""
    exclusions: list[Exclusion] = Field(default_factory=list)
    accepted_risks: list[AcceptedRiskWaiver] = Field(
        default_factory=list,
        json_schema_extra={"x-licenselens-mergeable": True},
    )
    backend_preferences: BackendPreferences = Field(default_factory=BackendPreferences)
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)
    custom_rules: list[CustomRule] = Field(
        default_factory=list,
        json_schema_extra={"x-licenselens-mergeable": True},
    )

    @model_validator(mode="after")
    def reject_unsupported_schema_version(self) -> Self:
        version = str(self.schema_version)
        major = version.split(".", maxsplit=1)[0]
        if major != SUPPORTED_SCHEMA_MAJOR:
            raise UnsupportedSchemaVersionError(schema_version=version)
        return self

    @field_validator(
        "packs",
        "check_ids",
        "sensitive_users",
        "sensitive_domains",
        "allowed_forwarding_domains",
    )
    @classmethod
    def reject_duplicate_strings(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            msg = "duplicate value"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def reject_duplicate_nested_ids(self) -> Self:
        for label, values in (
            ("custom rule", [rule.id for rule in self.custom_rules]),
            ("accepted risk", [risk.id for risk in self.accepted_risks]),
            ("exclusion", [exclusion.id for exclusion in self.exclusions]),
        ):
            if len(values) != len(set(values)):
                msg = f"duplicate {label} id"
                raise ValueError(msg)
        return self


class ConfigSchema(StrictConfigModel):
    profiles: list[AssessmentProfile]

    @model_validator(mode="after")
    def reject_duplicate_profile_ids(self) -> Self:
        profile_ids = [profile.id for profile in self.profiles]
        if len(profile_ids) != len(set(profile_ids)):
            msg = "duplicate profile id"
            raise ValueError(msg)
        return self


def write_config_schema(path: Path) -> Path:
    schema_text = json.dumps(AssessmentProfile.model_json_schema(), indent=2, sort_keys=True) + "\n"
    path.write_text(schema_text, encoding="utf-8")
    return path

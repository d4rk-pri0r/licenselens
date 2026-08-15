from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NewType

from pydantic import BaseModel, ConfigDict, Field

type JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
SchemaVersion = NewType("SchemaVersion", str)
ProfileId = NewType("ProfileId", str)
SourceReferenceId = NewType("SourceReferenceId", str)
AcceptedRiskId = NewType("AcceptedRiskId", str)

CURRENT_SCHEMA_VERSION: Final[SchemaVersion] = SchemaVersion("1.0")
SUPPORTED_SCHEMA_MAJOR: Final = "1"


@dataclass(frozen=True, slots=True)
class UnsupportedSchemaVersionError(Exception):
    schema_version: str

    def __str__(self) -> str:
        return f"unsupported assessment schema version: {self.schema_version}"


class EvaluationMode(StrEnum):
    DIRECT = "direct"
    PROXY = "proxy"
    MANUAL = "manual"
    UNSUPPORTED = "unsupported"
    DIRECT_WITH_PROXY_FALLBACK = "direct_with_proxy_fallback"


class CollectionStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"


class SourceReference(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: SourceReferenceId
    kind: str
    name: str
    reference: str
    collected_at: str | None = None


class CollectionSummary(BaseModel):
    model_config = ConfigDict(extra="allow")

    collector: str
    status: CollectionStatus
    source: str = ""
    items_collected: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class AcceptedRiskAnnotation(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: AcceptedRiskId
    check_id: str
    profile_id: ProfileId | None = None
    owner: str
    reason: str
    expires_on: str | None = None
    source: str = ""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NewType

from licenselens.schema_contracts import CollectionStatus, JsonValue

EvidenceKey = NewType("EvidenceKey", str)
CollectorId = NewType("CollectorId", str)
CheckId = NewType("CheckId", str)


class CloudEnvironment(StrEnum):
    PUBLIC = "public"
    US_GOV = "us_gov"
    CHINA = "china"


class EvidenceHealth(StrEnum):
    OK = "ok"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    TRUNCATED = "truncated"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class PaginationMetadata:
    pages_read: int = 0
    max_pages: int | None = None
    next_link_seen: bool = False

    @property
    def truncated(self) -> bool:
        return self.next_link_seen


@dataclass(frozen=True, slots=True)
class CollectionMetadata:
    source: str = ""
    items_collected: int = 0
    pagination: PaginationMetadata = PaginationMetadata()


@dataclass(frozen=True, slots=True)
class EvidenceEnvelope:
    key: EvidenceKey
    health: EvidenceHealth
    value: JsonValue = None
    metadata: CollectionMetadata = CollectionMetadata()
    reason: str = ""

    @property
    def is_usable(self) -> bool:
        return self.health is EvidenceHealth.OK

    @property
    def collection_status(self) -> CollectionStatus:
        match self.health:
            case EvidenceHealth.OK:
                return CollectionStatus.SUCCESS
            case EvidenceHealth.TRUNCATED:
                return CollectionStatus.PARTIAL
            case EvidenceHealth.DENIED | EvidenceHealth.ERROR | EvidenceHealth.MISSING:
                return CollectionStatus.FAILED
            case EvidenceHealth.UNAVAILABLE:
                return CollectionStatus.SKIPPED
            case EvidenceHealth.UNSUPPORTED:
                return CollectionStatus.UNSUPPORTED
            case unreachable:
                from typing import assert_never

                assert_never(unreachable)

    @classmethod
    def denied(cls, key: EvidenceKey, *, reason: str) -> EvidenceEnvelope:
        return cls(key=key, health=EvidenceHealth.DENIED, reason=reason)

    @classmethod
    def unavailable(cls, key: EvidenceKey, *, reason: str) -> EvidenceEnvelope:
        return cls(key=key, health=EvidenceHealth.UNAVAILABLE, reason=reason)

    @classmethod
    def unsupported(cls, key: EvidenceKey, *, reason: str) -> EvidenceEnvelope:
        return cls(key=key, health=EvidenceHealth.UNSUPPORTED, reason=reason)

    @classmethod
    def error(cls, key: EvidenceKey, *, reason: str) -> EvidenceEnvelope:
        return cls(key=key, health=EvidenceHealth.ERROR, reason=reason)

    @classmethod
    def truncated(
        cls,
        key: EvidenceKey,
        *,
        reason: str,
        metadata: CollectionMetadata,
    ) -> EvidenceEnvelope:
        return cls(
            key=key,
            health=EvidenceHealth.TRUNCATED,
            metadata=metadata,
            reason=reason,
        )

    @classmethod
    def missing(cls, key: EvidenceKey) -> EvidenceEnvelope:
        return cls(key=key, health=EvidenceHealth.MISSING, reason="evidence was not collected")


type CollectionOutcome = EvidenceEnvelope

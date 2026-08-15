"""Typed scan results for the provenance policy scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Final, Literal


class ScanMode(StrEnum):
    WORKSPACE = "workspace"
    GIT_REACHABLE = "git-reachable"
    GIT_ALL_OBJECTS = "git-all-objects"
    ARTIFACTS = "artifacts"


class ViolationKind(StrEnum):
    CONTENT = "content"
    PATH = "path"
    SYMLINK_TARGET = "symlink_target"
    ARCHIVE_MEMBER = "archive_member"
    ARCHIVE_CONTENT = "archive_content"
    BINARY = "binary"
    GIT_MESSAGE = "git_message"
    GIT_METADATA = "git_metadata"
    GIT_OBJECT = "git_object"
    MALFORMED_ARCHIVE = "malformed_archive"
    UNREADABLE = "unreadable"
    POLICY = "policy"


@dataclass(frozen=True, slots=True)
class Violation:
    """One fail-closed provenance policy hit."""

    kind: ViolationKind
    path: str
    detail: str
    mode: ScanMode
    object_id: str | None = None
    member: str | None = None
    offset: int | None = None
    snippet_hex: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["kind"] = self.kind.value
        payload["mode"] = self.mode.value
        # Drop nulls for stable compact JSON while keeping key order via sort later.
        return {key: value for key, value in payload.items() if value is not None}


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Deterministic scan outcome."""

    status: Literal["clean", "violations"]
    mode: ScanMode
    root: str
    violations: tuple[Violation, ...] = field(default_factory=tuple)
    allowed_row_sha256: str | None = None
    policy_readme: str | None = None
    scanned_paths: int = 0

    @property
    def findings(self) -> list[Violation]:
        return list(self.violations)

    @property
    def hits(self) -> list[Violation]:
        return list(self.violations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "mode": self.mode.value,
            "root": self.root,
            "policy_readme": self.policy_readme,
            "allowed_row_sha256": self.allowed_row_sha256,
            "scanned_paths": self.scanned_paths,
            "violation_count": len(self.violations),
            "violations": [item.to_dict() for item in self.violations],
        }


JSON_SEPARATORS: Final = (",", ":")

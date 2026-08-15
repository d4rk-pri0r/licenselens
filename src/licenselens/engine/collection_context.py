"""Typed scan collection context shared by runtime collector closures."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from licenselens.auth import AuthContext
from licenselens.graph import GraphClient
from licenselens.models import SubscribedSku

WarningSink = Callable[[str], None]


@dataclass(slots=True)
class ScanCollectionContext:
    """Runtime inputs for selected-check evidence collection."""

    scan_mode: str
    auth: AuthContext
    client: GraphClient | None
    skus: list[SubscribedSku]
    warnings: list[str]
    workspace_resource_id: str | None = None
    allow_email_proxy: bool = False
    discover_workspaces: bool = False
    extras: dict[str, Any] = field(default_factory=dict)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    @property
    def is_dry_run(self) -> bool:
        return self.scan_mode == "dry_run"

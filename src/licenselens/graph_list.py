"""Graph collection page-walk result type."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from licenselens.collectors.contracts import PaginationMetadata


@dataclass(frozen=True, slots=True)
class GraphListResult:
    items: tuple[dict[str, Any], ...]
    pages_read: int
    max_pages: int
    next_link_seen: bool

    @property
    def truncated(self) -> bool:
        return self.next_link_seen

    @property
    def pagination(self) -> PaginationMetadata:
        return PaginationMetadata(
            pages_read=self.pages_read,
            max_pages=self.max_pages,
            next_link_seen=self.next_link_seen,
        )

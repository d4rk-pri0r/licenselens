"""Central Graph/REST operation registry (paths, permissions, clouds)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from licenselens.graph_ops_catalog import build_operations
from licenselens.graph_ops_types import (
    ApiFamily,
    GraphOperation,
    PreviewApiVersionError,
    WritePermissionError,
    reject_write_permission,
)

__all__ = [
    "ApiFamily",
    "GraphOperation",
    "PreviewApiVersionError",
    "WritePermissionError",
    "all_application_permissions",
    "get_operation",
    "iter_operations",
    "operations_by_family",
    "reject_write_permission",
]

_OPERATIONS: Final[tuple[GraphOperation, ...]] = build_operations()
_BY_ID: Final[Mapping[str, GraphOperation]] = {op.operation_id: op for op in _OPERATIONS}


def get_operation(operation_id: str) -> GraphOperation:
    try:
        return _BY_ID[operation_id]
    except KeyError as exc:
        raise KeyError(f"unknown graph operation: {operation_id}") from exc


def iter_operations() -> tuple[GraphOperation, ...]:
    return _OPERATIONS


def operations_by_family(family: ApiFamily) -> tuple[GraphOperation, ...]:
    return tuple(op for op in _OPERATIONS if op.family is family)


def all_application_permissions(*, family: ApiFamily | None = ApiFamily.GRAPH) -> tuple[str, ...]:
    perms: set[str] = set()
    for op in _OPERATIONS:
        if family is not None and op.family is not family:
            continue
        perms.update(op.application_permissions)
    return tuple(sorted(perms))

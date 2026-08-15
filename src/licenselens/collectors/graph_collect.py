"""Shared Graph operation runner → EvidenceEnvelope mapping."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from licenselens.collectors.contracts import (
    CloudEnvironment,
    CollectionMetadata,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
    PaginationMetadata,
)
from licenselens.errors import AuthError, GraphError
from licenselens.graph import GraphClient, GraphListResult
from licenselens.graph_ops import GraphOperation, get_operation
from licenselens.schema_contracts import JsonValue


class SupportsGraphReads(Protocol):
    cloud: CloudEnvironment
    allow_preview: bool

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]: ...

    def get_list_result(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        max_pages: int = 50,
    ) -> GraphListResult: ...


def collect_graph_operation(
    client: SupportsGraphReads,
    operation_id: str,
    *,
    params: Mapping[str, str] | None = None,
    path_override: str | None = None,
) -> EvidenceEnvelope:
    """Execute a declared Graph operation and wrap the result as EvidenceEnvelope."""
    operation = get_operation(operation_id)
    key = EvidenceKey(operation.evidence_key)

    if client.cloud not in operation.supported_clouds:
        return EvidenceEnvelope.unsupported(
            key,
            reason=(
                f"operation {operation.operation_id} does not support cloud {client.cloud.value}"
            ),
        )

    if operation.preview and not client.allow_preview:
        return EvidenceEnvelope.unsupported(
            key,
            reason=f"preview operation {operation.operation_id} requires allow_preview",
        )

    path = path_override or operation.path
    query = dict(params) if params else None

    try:
        if operation.is_collection:
            result = client.get_list_result(path, params=query, max_pages=operation.max_pages)
            return _envelope_from_list(key, operation, result)
        payload = client.get(path, params=query)
        return EvidenceEnvelope(
            key=key,
            health=EvidenceHealth.OK,
            value=_as_json(payload),
            metadata=CollectionMetadata(
                source=operation.operation_id,
                items_collected=1,
                pagination=PaginationMetadata(pages_read=1, max_pages=1),
            ),
        )
    except AuthError as exc:
        return EvidenceEnvelope.denied(key, reason=str(exc))
    except GraphError as exc:
        return map_graph_error(key, exc, source=operation.operation_id)


def map_graph_error(
    key: EvidenceKey,
    exc: GraphError,
    *,
    source: str = "",
) -> EvidenceEnvelope:
    status = exc.status_code
    reason = str(exc)
    if status in {401, 403}:
        return EvidenceEnvelope.denied(key, reason=reason)
    if status == 404:
        return EvidenceEnvelope.unavailable(key, reason=reason)
    if status == 429:
        return EvidenceEnvelope.error(key, reason=f"throttled: {reason}")
    return EvidenceEnvelope.error(key, reason=reason)


def _envelope_from_list(
    key: EvidenceKey,
    operation: GraphOperation,
    result: GraphListResult,
) -> EvidenceEnvelope:
    metadata = CollectionMetadata(
        source=operation.operation_id,
        items_collected=len(result.items),
        pagination=result.pagination,
    )
    value: JsonValue = [_as_json(item) for item in result.items]
    if result.truncated:
        return EvidenceEnvelope(
            key=key,
            health=EvidenceHealth.TRUNCATED,
            value=value,
            metadata=metadata,
            reason=(f"truncated after {result.pages_read} pages (max_pages={result.max_pages})"),
        )
    return EvidenceEnvelope(
        key=key,
        health=EvidenceHealth.OK,
        value=value,
        metadata=metadata,
    )


def _as_json(value: dict[str, Any]) -> dict[str, JsonValue]:
    return {str(k): _coerce(v) for k, v in value.items()}


def _coerce(value: Any) -> JsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_coerce(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _coerce(v) for k, v in value.items()}
    return str(value)


def ensure_graph_client_cloud(client: GraphClient, cloud: CloudEnvironment) -> None:
    if client.cloud is not cloud:
        raise GraphError(
            f"GraphClient cloud {client.cloud.value} does not match requested {cloud.value}",
            status_code=400,
        )

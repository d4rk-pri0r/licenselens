"""Parse bridge JSON into typed power-data models (boundary parse)."""

from __future__ import annotations

from typing import assert_never

from pydantic import ValidationError

from licenselens.collectors.exchange_models import PolicyItem, PolicyKind, SurfaceStatus
from licenselens.collectors.power_data_models import (
    COVERAGE_SURFACE_MAP,
    MANUAL_PORTAL_POLICY_IDS,
    CoverageRowEvidence,
    PowerDataAdapterPayload,
    PowerDataBundle,
    PowerDataSurface,
)
from licenselens.schema_contracts import JsonValue


class PowerDataPayloadParseError(Exception):
    """Bridge data could not be normalized into power-data models."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)

    def __str__(self) -> str:
        return f"power-data payload parse error: {self.reason}"


def normalize_adapter_payload(raw: JsonValue, *, adapter: str) -> PowerDataAdapterPayload:
    """Parse one adapter `data` object into PowerDataAdapterPayload."""
    if not isinstance(raw, dict):
        msg = "adapter data is not an object"
        raise PowerDataPayloadParseError(msg)

    surfaces_raw = raw.get("surfaces")
    surfaces: dict[str, PowerDataSurface] = {}
    if isinstance(surfaces_raw, dict):
        for key, value in surfaces_raw.items():
            surfaces[str(key)] = _normalize_surface(value, fallback_name=str(key))
    elif surfaces_raw is not None:
        msg = "surfaces must be an object"
        raise PowerDataPayloadParseError(msg)

    collected_at = raw.get("collected_at")
    collected = collected_at if isinstance(collected_at, str) else None
    surface_dump = {name: surface.model_dump(mode="json") for name, surface in surfaces.items()}
    try:
        return PowerDataAdapterPayload.model_validate(
            {
                "adapter": str(raw.get("adapter") or adapter),
                "module": str(raw.get("module") or ""),
                "collection": str(raw.get("collection") or ""),
                "surfaces": surface_dump,
                "collected_at": collected,
                "source": "powershell.bridge",
                "proxy": False,
            }
        )
    except ValidationError as exc:
        raise PowerDataPayloadParseError(str(exc)) from exc


def surface_status_from_health(code: str) -> SurfaceStatus:
    """Map bridge/error codes onto SurfaceStatus."""
    match code:
        case "ok":
            return SurfaceStatus.OK
        case "denied":
            return SurfaceStatus.DENIED
        case "unsupported" | "unsupported_cloud":
            return SurfaceStatus.UNSUPPORTED
        case "module_missing" | "unavailable":
            return SurfaceStatus.UNAVAILABLE
        case "disconnected":
            return SurfaceStatus.DISCONNECTED
        case "error" | "adapter_failed":
            return SurfaceStatus.ERROR
        case _:
            return SurfaceStatus.ERROR


def unavailable_payload(
    adapter: str,
    *,
    reason: str,
    status: SurfaceStatus,
) -> PowerDataAdapterPayload:
    """Build a typed empty payload for module/session failures."""
    return PowerDataAdapterPayload(
        adapter=adapter,
        module="",
        collection=adapter,
        surfaces={
            "adapter": PowerDataSurface(
                surface="adapter",
                status=status,
                reason=reason,
                items=[],
                raw_count=0,
            )
        },
        source="powershell.bridge",
        proxy=False,
    )


def coverage_evidence_for_bundle(bundle: PowerDataBundle) -> list[CoverageRowEvidence]:
    """Emit explicit evidence/unsupported/manual state for every power coverage row."""
    rows: list[CoverageRowEvidence] = []
    for policy_id, (adapter_name, surface_name) in COVERAGE_SURFACE_MAP.items():
        status, reason = bundle.coverage_row_state(policy_id)
        portal_only = policy_id in MANUAL_PORTAL_POLICY_IDS
        rows.append(
            CoverageRowEvidence(
                policy_id=policy_id,
                status=status,
                reason=reason,
                adapter=adapter_name,
                surface=surface_name,
                portal_only=portal_only,
            )
        )
    return rows


def _normalize_surface(raw: JsonValue, *, fallback_name: str) -> PowerDataSurface:
    if not isinstance(raw, dict):
        return PowerDataSurface(
            surface=fallback_name,
            status=SurfaceStatus.ERROR,
            reason="surface is not an object",
        )

    status_raw = raw.get("status")
    status_text = status_raw if isinstance(status_raw, str) else "error"
    status = _parse_surface_status(status_text)

    items_raw = raw.get("items")
    items: list[PolicyItem] = []
    if isinstance(items_raw, list):
        for entry in items_raw:
            item = _normalize_item(entry)
            if item is not None:
                items.append(item)

    raw_count = raw.get("raw_count")
    count = raw_count if isinstance(raw_count, int) else len(items)
    reason = raw.get("reason")
    reason_text = str(reason) if isinstance(reason, str) else ""
    surface_name = raw.get("surface")
    name = str(surface_name) if isinstance(surface_name, str) else fallback_name
    portal_raw = raw.get("portal_only")
    portal_only = (
        bool(portal_raw)
        if isinstance(portal_raw, bool)
        else ("portal-only" in reason_text.lower() or "manual" in reason_text.lower())
    )
    return PowerDataSurface(
        surface=name,
        status=status,
        reason=reason_text,
        items=items,
        raw_count=count,
        portal_only=portal_only,
    )


def _normalize_item(raw: JsonValue) -> PolicyItem | None:
    if not isinstance(raw, dict):
        return None
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        return None
    kind_raw = raw.get("kind")
    kind = _parse_policy_kind(kind_raw if isinstance(kind_raw, str) else "custom")
    enabled_raw = raw.get("enabled")
    enabled: bool | None
    if isinstance(enabled_raw, bool):
        enabled = enabled_raw
    else:
        enabled = None
    identity_raw = raw.get("identity")
    identity = identity_raw if isinstance(identity_raw, str) else None
    props_raw = raw.get("properties")
    properties: dict[str, JsonValue] = {}
    if isinstance(props_raw, dict):
        properties = {str(k): v for k, v in props_raw.items()}
    assigns_raw = raw.get("assignments")
    assignments: list[str] = []
    if isinstance(assigns_raw, list):
        assignments = [str(a) for a in assigns_raw]
    return PolicyItem(
        name=name,
        identity=identity,
        kind=kind,
        enabled=enabled,
        properties=properties,
        assignments=assignments,
    )


def _parse_surface_status(value: str) -> SurfaceStatus:
    normalized = value.strip().lower()
    match normalized:
        case "ok":
            return SurfaceStatus.OK
        case "denied":
            return SurfaceStatus.DENIED
        case "unavailable":
            return SurfaceStatus.UNAVAILABLE
        case "unsupported":
            return SurfaceStatus.UNSUPPORTED
        case "error":
            return SurfaceStatus.ERROR
        case "disconnected":
            return SurfaceStatus.DISCONNECTED
        case _:
            return SurfaceStatus.ERROR


def _parse_policy_kind(value: str) -> PolicyKind:
    normalized = value.strip().lower()
    match normalized:
        case "default" | "global":
            return PolicyKind.DEFAULT
        case "custom":
            return PolicyKind.CUSTOM
        case "preset_standard":
            return PolicyKind.PRESET_STANDARD
        case "preset_strict":
            return PolicyKind.PRESET_STRICT
        case "effective":
            return PolicyKind.EFFECTIVE
        case _:
            return PolicyKind.CUSTOM


def assert_surface_status_exhaustive(status: SurfaceStatus) -> str:
    """Helper for callers that need exhaustive SurfaceStatus handling."""
    match status:
        case SurfaceStatus.OK:
            return "ok"
        case SurfaceStatus.DENIED:
            return "denied"
        case SurfaceStatus.UNAVAILABLE:
            return "unavailable"
        case SurfaceStatus.UNSUPPORTED:
            return "unsupported"
        case SurfaceStatus.ERROR:
            return "error"
        case SurfaceStatus.DISCONNECTED:
            return "disconnected"
        case unreachable:
            assert_never(unreachable)

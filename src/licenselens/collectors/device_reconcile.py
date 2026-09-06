"""Join Entra, Intune, and MDE device inventories into coverage denominators."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

__all__ = ["reconcile"]

_LIST_CAP = 50


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _guid(value: object) -> str:
    return str(value or "").strip().lower()


def _parse_dt(value: object) -> datetime | None:
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _within(value: object, cutoff: datetime) -> bool:
    dt = _parse_dt(value)
    return dt is not None and dt >= cutoff


def _ratio(num: int, den: int) -> float | None:
    if den <= 0:
        return None
    return num / den


def _capped(ids: set[str]) -> tuple[list[str], bool]:
    ordered = sorted(ids)
    return ordered[:_LIST_CAP], len(ordered) > _LIST_CAP


def reconcile(
    entra: dict[str, Any] | None,
    intune: dict[str, Any] | None,
    mde: dict[str, Any] | None,
    *,
    active_days: int = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return coverage denominators from three bounded inventories."""
    now_utc = (now or datetime.now(UTC)).astimezone(UTC)
    cutoff = now_utc - timedelta(days=active_days)

    entra_d = _as_dict(entra)
    intune_d = _as_dict(intune)
    mde_d = _as_dict(mde)

    entra_rows = [row for row in (entra_d.get("devices") or []) if isinstance(row, dict)]
    raw_intune = intune_d.get("managed_devices") or intune_d.get("devices") or []
    intune_rows = [row for row in raw_intune if isinstance(row, dict)]
    raw_mde = mde_d.get("machines") or mde_d.get("devices") or []
    mde_rows = [row for row in raw_mde if isinstance(row, dict)]

    entra_active: set[str] = set()
    entra_all: set[str] = set()
    for row in entra_rows:
        did = _guid(row.get("deviceId") or row.get("id"))
        if not did:
            continue
        entra_all.add(did)
        enabled = row.get("accountEnabled")
        if enabled is False:
            continue
        if _within(row.get("approximateLastSignInDateTime"), cutoff):
            entra_active.add(did)

    intune_managed: set[str] = set()
    intune_active: set[str] = set()
    for row in intune_rows:
        did = _guid(row.get("azureADDeviceId") or row.get("azureAdDeviceId"))
        if not did:
            continue
        intune_managed.add(did)
        if _within(row.get("lastSyncDateTime"), cutoff):
            intune_active.add(did)

    mde_active: set[str] = set()
    mde_all: set[str] = set()
    for row in mde_rows:
        did = _guid(row.get("aadDeviceId") or row.get("aad_device_id"))
        if not did:
            continue
        mde_all.add(did)
        onboarded = str(row.get("onboardingStatus") or "") == "Onboarded"
        if onboarded and _within(row.get("lastSeen"), cutoff):
            mde_active.add(did)

    intune_not_onboarded, list_trunc_a = _capped(intune_active - mde_active)
    mde_only, list_trunc_b = _capped(mde_active - intune_managed)
    entra_unmanaged, list_trunc_c = _capped(entra_active - intune_managed)
    truncated = bool(
        entra_d.get("truncated")
        or intune_d.get("truncated")
        or mde_d.get("truncated")
        or list_trunc_a
        or list_trunc_b
        or list_trunc_c
    )
    return {
        "intune_active": len(intune_active),
        "mde_active": len(mde_active),
        "entra_active": len(entra_active),
        "intune_managed": len(intune_managed),
        "mde_coverage_of_intune": _ratio(len(intune_active & mde_active), len(intune_active)),
        "intune_coverage_of_entra": _ratio(len(entra_active & intune_managed), len(entra_active)),
        "intune_not_onboarded": intune_not_onboarded,
        "mde_only": mde_only,
        "entra_unmanaged": entra_unmanaged,
        "truncated": truncated,
        "window_days": active_days,
        "denominator_source_mde": "intune_managed_active_30d",
        "denominator_source_intune": "entra_devices_active_30d",
    }

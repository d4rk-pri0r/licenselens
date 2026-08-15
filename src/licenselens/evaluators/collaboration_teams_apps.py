"""Teams app-management evaluators (SCuBA MS.TEAMS.5.* rows)."""

from __future__ import annotations

from typing import Any, Final

from licenselens.collectors.collaboration_models import SurfaceStatus
from licenselens.evaluators.collaboration_lib import (
    collaboration_bundle,
    direct_meta,
    items,
    prop_str,
    surface,
    unavailable,
    usable,
)
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus

_TEAMS_APPS: Final = "teams_apps"
_APPS_SURFACE: Final = "app_permission_policies"
_V2_SURFACE: Final = "app_settings_v2"
_V2_LIMITATION: Final = (
    "Org-wide app settings (v2) were not readable; only legacy permission policies were evaluated."
)


def _apps_state(
    bundle: Any,
    catalog_prop: str,
) -> tuple[str, list[str], dict[str, Any], bool]:
    if not usable(bundle, _TEAMS_APPS, _APPS_SURFACE):
        return "unavailable", [], {"readable": False}, False
    all_items = items(bundle, _TEAMS_APPS, _APPS_SURFACE)
    if not all_items:
        return "empty", [], {}, False
    weak = []
    observed: dict[str, Any] = {}
    for item in all_items:
        catalog = prop_str(item, catalog_prop).strip().lower()
        observed[item.name or item.identity or "?"] = catalog
        if catalog == "allowedapplist":
            weak.append(item.name or item.identity or "?")
    v2_surface = surface(bundle, _TEAMS_APPS, _V2_SURFACE)
    v2_unreadable = v2_surface is None or v2_surface.status is not SurfaceStatus.OK
    state = "gap" if weak else "ok"
    return state, weak, {"catalog_types": observed}, v2_unreadable


def _apps_result(
    *,
    state: str,
    weak_names: list[str],
    evidence: dict[str, Any],
    v2_unreadable: bool,
    label: str,
    ok_summary: str,
    gap_summary: str,
    customer_ok: str,
    customer_gap: str,
) -> Evaluation:
    limitations: list[str] = []
    if v2_unreadable:
        limitations.append(_V2_LIMITATION)
        evidence = {
            **evidence,
            "v2_readable": False,
            "required_surface_incomplete": True,
            "required_surface": _V2_SURFACE,
        }
    else:
        evidence = {**evidence, "v2_readable": True, "required_surface_incomplete": False}

    if state == "unavailable":
        return unavailable(
            f"{label} app permission policies could not be read; treated as unresolved.",
            adapter=_TEAMS_APPS,
            surface_name=_APPS_SURFACE,
            customer_summary=f"We could not confirm how {label} apps are governed.",
        )
    if state == "empty":
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=f"No {label} app permission policies were returned.",
            evidence=evidence,
            customer_summary=f"Confirm how {label} apps are governed in the Teams admin center.",
            confidence=Confidence.MEDIUM,
            limitations=limitations or ["No app permission policies were collected."],
        )
    if state == "gap":
        evidence["weak_policies"] = weak_names
        meta = direct_meta()
        # Real gaps stay gaps even when v2 is unreadable; never claim high confidence
        # without the required org-wide surface.
        confidence = Confidence.MEDIUM if v2_unreadable else meta["confidence"]
        return Evaluation(
            status=FindingStatus.GAP,
            summary=f"{gap_summary} ({', '.join(weak_names)}).",
            evidence=evidence,
            customer_summary=customer_gap,
            confidence=confidence,
            data_sources=list(meta["data_sources"]),
            limitations=limitations,
        )

    # Compliant legacy policies alone are not enough when required v2 is unreadable.
    if v2_unreadable:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"{ok_summary.rstrip('.')} (partial: org-wide app settings v2 were not readable)."
            ),
            evidence=evidence,
            customer_summary=(
                f"{customer_ok.rstrip('.')} "
                "Org-wide app settings could not be confirmed automatically."
            ),
            confidence=Confidence.MEDIUM,
            data_sources=list(direct_meta()["data_sources"]),
            limitations=limitations,
        )

    return Evaluation(
        status=FindingStatus.OK,
        summary=ok_summary,
        evidence=evidence,
        customer_summary=customer_ok,
        **direct_meta(),
    )


def evaluate_teams_microsoft_apps_governed(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs, v2 = _apps_state(bundle, "DefaultCatalogAppsType")
    return _apps_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        v2_unreadable=v2,
        label="Microsoft",
        ok_summary="Microsoft app installation is not open to all.",
        gap_summary="Microsoft apps are open to all for some users",
        customer_ok="Microsoft apps are governed by policy.",
        customer_gap="Some users can install any Microsoft app. Restrict to approved apps.",
    )


def evaluate_teams_third_party_apps_governed(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs, v2 = _apps_state(bundle, "GlobalCatalogAppsType")
    return _apps_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        v2_unreadable=v2,
        label="third-party",
        ok_summary="Third-party app installation is not open to all.",
        gap_summary="Third-party apps are open to all for some users",
        customer_ok="Third-party apps are governed by policy.",
        customer_gap="Some users can install any third-party app. Restrict to approved apps.",
    )


def evaluate_teams_custom_apps_governed(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = collaboration_bundle(evidence)
    state, weak, obs, v2 = _apps_state(bundle, "PrivateCatalogAppsType")
    return _apps_result(
        state=state,
        weak_names=weak,
        evidence=obs,
        v2_unreadable=v2,
        label="custom",
        ok_summary="Custom app installation is not open to all.",
        gap_summary="Custom apps are open to all for some users",
        customer_ok="Custom apps are governed by policy.",
        customer_gap="Some users can install any custom app. Restrict to approved apps.",
    )

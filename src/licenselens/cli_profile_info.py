"""Assessment-profile requirement and checks-table helpers for the CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from licenselens.cli_scan_config import ScanConfigError
from licenselens.config_models import BackendPreference
from licenselens.engine.loader import load_checks
from licenselens.engine.profiles import (
    ProfileReferenceError,
    compose_profile,
    load_builtin_profiles,
)
from licenselens.engine.registry import default_registry
from licenselens.models import CheckDefinition

BACKEND_MODULE_LABELS: Final[dict[BackendPreference, str]] = {
    BackendPreference.GRAPH: "Microsoft Graph",
    BackendPreference.ARM: "Azure Resource Manager",
    BackendPreference.EXCHANGE_ONLINE: "ExchangeOnlineManagement",
    BackendPreference.DEFENDER: "Microsoft.Graph / MDE API",
    BackendPreference.SECURE_SCORE: "Microsoft Graph (Secure Score)",
    BackendPreference.MANUAL: "manual evidence",
}

_REGISTRY_BACKEND_MODULES: Final[dict[str, str]] = {
    "graph": "Microsoft Graph",
    "mde": "Microsoft Defender for Endpoint API",
    "arm": "Azure Resource Manager",
    "proxy": "Secure Score proxy",
    "noop": "none",
}


@dataclass(frozen=True, slots=True)
class ProfileRequirementReport:
    profile_id: str
    profile_name: str
    check_ids: tuple[str, ...]
    capabilities: tuple[str, ...]
    permissions: tuple[str, ...]
    backends: tuple[str, ...]
    modules: tuple[str, ...]


def profile_requirement_report(profile_id: str) -> ProfileRequirementReport:
    try:
        resolved = compose_profile(profile_id.strip())
    except ProfileReferenceError as exc:
        raise ScanConfigError(str(exc)) from exc

    checks_by_id = {check.id: check for check in load_checks()}
    selected = [
        checks_by_id[check_id]
        for check_id in resolved.selected_check_ids
        if check_id in checks_by_id
    ]
    capabilities = sorted({cap for check in selected for cap in check.required_capabilities})
    registry = default_registry()
    permissions: set[str] = set()
    backends: set[str] = {
        preference.value for preference in resolved.profile.backend_preferences.preferred
    }
    for check in selected:
        evaluator = registry.evaluators.get(check.id)
        if evaluator is None:
            continue
        permissions.update(evaluator.permissions)
        backends.add(evaluator.backend.value)
        for source_id in evaluator.input_models:
            source = registry.data_sources.get(source_id)
            if source is not None:
                permissions.update(source.permissions)
                backends.add(source.backend.value)

    modules = sorted(
        {
            BACKEND_MODULE_LABELS.get(preference, preference.value)
            for preference in resolved.profile.backend_preferences.preferred
        }
        | {_module_for_backend_name(name) for name in backends}
    )
    return ProfileRequirementReport(
        profile_id=str(resolved.profile.id),
        profile_name=resolved.profile.name,
        check_ids=tuple(resolved.selected_check_ids),
        capabilities=tuple(capabilities),
        permissions=tuple(sorted(permissions)),
        backends=tuple(sorted(backends)),
        modules=tuple(modules),
    )


def checks_listing_rows(
    checks: list[CheckDefinition],
) -> list[tuple[str, str, str, str, str, str, str]]:
    profiles = load_builtin_profiles()
    profile_ids_by_check: dict[str, list[str]] = {check.id: [] for check in checks}
    for profile in profiles:
        resolved = compose_profile(str(profile.id), checks=checks)
        for check_id in resolved.selected_check_ids:
            profile_ids_by_check.setdefault(check_id, []).append(str(profile.id))

    registry = default_registry()
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    for check in checks:
        evaluator = registry.evaluators.get(check.id)
        backend = evaluator.backend.value if evaluator is not None else check.collector
        mode = evaluator.evaluation_mode.value if evaluator is not None else "direct"
        state = "enabled" if check.enabled else "disabled"
        profile_list = ",".join(profile_ids_by_check.get(check.id, [])) or "—"
        rows.append(
            (
                check.id,
                check.workload.value,
                check.severity.value,
                profile_list,
                backend,
                mode,
                state,
            )
        )
    return rows


def _module_for_backend_name(name: str) -> str:
    try:
        preference = BackendPreference(name)
    except ValueError:
        return _REGISTRY_BACKEND_MODULES.get(name, name)
    return BACKEND_MODULE_LABELS.get(preference, preference.value)

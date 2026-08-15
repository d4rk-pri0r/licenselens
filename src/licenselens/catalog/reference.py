from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Final

import yaml
from pydantic import TypeAdapter

from licenselens.auth import REQUIRED_GRAPH_APP_PERMISSIONS
from licenselens.catalog._reference_coverage import load_coverage_rows
from licenselens.catalog._reference_models import (
    ReferenceCapability,
    ReferenceCatalogError,
    ReferenceCheck,
    ReferenceModel,
    ReferenceModelPaths,
    ReferenceProfile,
    SupportState,
)
from licenselens.catalog.loader import load_capabilities
from licenselens.config_models import AssessmentProfile
from licenselens.engine.loader import load_checks
from licenselens.engine.registry import AssessmentRegistry, default_registry
from licenselens.models import CheckDefinition, CheckPack
from licenselens.paths import catalog_dir, checks_dir
from licenselens.schema_contracts import EvaluationMode

type JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]

YAML_OBJECT: Final = TypeAdapter(JsonObject)
GRAPH_PERMISSION_ROW: Final = re.compile(r"^\| `([A-Za-z.]+)` \|")


def build_reference_model(paths: ReferenceModelPaths | None = None) -> ReferenceModel:
    source_paths = paths or _default_paths()
    capabilities = load_capabilities(source_paths.capabilities_path)
    checks = load_checks(source_paths.checks_root)
    profiles = _load_profiles(source_paths.profiles_root)
    documented_permissions, modules = _documented_permissions(source_paths.permission_docs_path)
    errors = _validate_permissions(documented_permissions)
    check_ids = {check.id for check in checks}
    errors.extend(_validate_capabilities({cap.id for cap in capabilities}, checks))
    errors.extend(_validate_checks(check_ids, checks))
    errors.extend(_validate_profiles(profiles, checks))
    coverage_rows, coverage_errors = load_coverage_rows(source_paths.coverage_path, check_ids)
    errors.extend(coverage_errors)
    if errors:
        raise ReferenceCatalogError(tuple(sorted(errors)))
    return ReferenceModel(
        capabilities=tuple(
            ReferenceCapability(
                id=cap.id,
                workloads=tuple(sorted(workload.value for workload in cap.workloads)),
                required_by_checks=tuple(
                    sorted(check.id for check in checks if cap.id in check.required_capabilities)
                ),
                service_plan_names=tuple(sorted(cap.service_plan_names)),
                sku_part_numbers=tuple(sorted(cap.sku_part_numbers)),
                service_plan_aliases=tuple(sorted(cap.service_plan_aliases)),
                sku_aliases=tuple(sorted(cap.sku_aliases)),
                entitlement_kind=cap.entitlement_kind,
                clouds=tuple(sorted(cap.clouds)),
                backends=tuple(sorted(cap.backends)),
                source_version=cap.source_version,
                docs_url=cap.docs_url,
            )
            for cap in sorted(capabilities, key=lambda item: item.id)
        ),
        checks=tuple(_reference_check(check) for check in sorted(checks, key=lambda item: item.id)),
        profiles=tuple(
            _reference_profile(profile, checks)
            for profile in sorted(profiles, key=lambda item: str(item.id))
        ),
        graph_permissions=tuple(sorted(REQUIRED_GRAPH_APP_PERMISSIONS)),
        permission_modules=tuple(sorted(modules)),
        coverage_rows=tuple(sorted(coverage_rows, key=lambda row: row.policy_id)),
    )


def dump_reference_json(model: ReferenceModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _default_paths() -> ReferenceModelPaths:
    catalog_root = catalog_dir()
    return ReferenceModelPaths(
        capabilities_path=catalog_root / "capabilities.yaml",
        checks_root=checks_dir(),
        profiles_root=catalog_root / "profiles",
        coverage_path=catalog_root / "coverage" / "scuba-2026-08.yaml",
        permission_docs_path=catalog_root.parent / "docs" / "permissions.md",
    )


def _load_profiles(root: Path) -> list[AssessmentProfile]:
    return [
        AssessmentProfile.model_validate(
            YAML_OBJECT.validate_python(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        )
        for path in sorted(root.glob("*.yaml"))
    ]


def _documented_permissions(path: Path) -> tuple[set[str], set[str]]:
    permissions: set[str] = set()
    modules: set[str] = set()
    section = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            section = line
        if "Microsoft Graph" in section:
            match = GRAPH_PERMISSION_ROW.match(line)
            if match:
                permissions.add(match.group(1))
        if section.startswith("## ") and line.startswith("| ") and "Purpose" not in line:
            modules.add(section.removeprefix("## ").strip())
    return permissions, modules


def _validate_permissions(documented: set[str]) -> list[str]:
    required = set(REQUIRED_GRAPH_APP_PERMISSIONS)
    return [
        *(f"undocumented_permission:{name}" for name in sorted(required - documented)),
        *(f"undeclared_permission:{name}" for name in sorted(documented - required)),
    ]


def _validate_capabilities(
    capability_ids: set[str],
    checks: list[CheckDefinition],
) -> list[str]:
    errors: list[str] = []
    for check in checks:
        errors.extend(
            f"unknown_capability:{check.id}:{capability_id}"
            for capability_id in sorted(set(check.required_capabilities) - capability_ids)
        )
    required_by: dict[str, list[str]] = {capability_id: [] for capability_id in capability_ids}
    for check in checks:
        for capability_id in check.required_capabilities:
            if capability_id in required_by:
                required_by[capability_id].append(check.id)
    errors.extend(
        f"empty_required_by_checks:{capability_id}"
        for capability_id, mapped in sorted(required_by.items())
        if not mapped
    )
    return errors


def _validate_checks(
    check_ids: set[str],
    checks: list[CheckDefinition],
    registry: AssessmentRegistry | None = None,
) -> list[str]:
    assessment = registry if registry is not None else default_registry()
    errors: list[str] = []
    for check in checks:
        if check.source_path is None:
            errors.append(f"missing_provenance:{check.id}:source_path")
        entry = assessment.evaluators.get(check.id)
        if entry is None or entry.evaluate is None:
            errors.append(f"missing_evaluator:{check.id}")
        if entry is None or not entry.input_models:
            errors.append(f"missing_evidence_keys:{check.id}")
    covered = {
        check_id
        for check_id in check_ids
        if (entry := assessment.evaluators.get(check_id)) is not None and entry.evaluate is not None
    }
    errors.extend(f"orphan_check:{check_id}" for check_id in sorted(check_ids - covered))
    return errors


def _validate_profiles(
    profiles: list[AssessmentProfile],
    checks: list[CheckDefinition],
) -> list[str]:
    check_ids = {check.id for check in checks}
    modeled_packs = {pack.value for pack in CheckPack}
    errors: list[str] = []
    for profile in profiles:
        errors.extend(
            f"unknown_profile_check:{profile.id}:{check_id}"
            for check_id in sorted(_profile_declared_check_ids(profile) - check_ids)
        )
        for pack in sorted(set(profile.packs) & modeled_packs):
            if not any(check.pack.value == pack for check in checks):
                errors.append(f"empty_profile_pack:{profile.id}:{pack}")
    return errors


def _reference_check(
    check: CheckDefinition,
    registry: AssessmentRegistry | None = None,
) -> ReferenceCheck:
    assessment = registry if registry is not None else default_registry()
    entry = assessment.evaluators.get(check.id)
    evidence_keys = tuple(sorted(entry.input_models)) if entry is not None else ()
    return ReferenceCheck(
        id=check.id,
        collector=check.collector,
        evidence_keys=evidence_keys,
        evaluator_registered=entry is not None and entry.evaluate is not None,
        required_capabilities=tuple(sorted(check.required_capabilities)),
        source_path=check.source_path or "",
        support_state=_support_state_from_registry(entry.evaluation_mode if entry else None),
    )


def _support_state_from_registry(mode: EvaluationMode | None) -> SupportState:
    if mode is None:
        raise ReferenceCatalogError(("missing_evaluation_mode",))
    try:
        return SupportState(mode.value)
    except ValueError as exc:
        raise ReferenceCatalogError((f"unknown_evaluation_mode:{mode.value}",)) from exc


def _reference_profile(
    profile: AssessmentProfile,
    checks: list[CheckDefinition],
) -> ReferenceProfile:
    declared = _profile_declared_check_ids(profile)
    resolved = declared | {check.id for check in checks if check.pack.value in set(profile.packs)}
    return ReferenceProfile(
        id=str(profile.id),
        packs=tuple(sorted(profile.packs)),
        check_ids=tuple(sorted(profile.check_ids)),
        resolved_check_ids=tuple(sorted(resolved)),
    )


def _profile_declared_check_ids(profile: AssessmentProfile) -> set[str]:
    return {
        *profile.check_ids,
        *(risk.check_id for risk in profile.accepted_risks),
        *(exclusion.check_id for exclusion in profile.exclusions),
    }

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml
from pydantic import TypeAdapter

from licenselens.config_models import AssessmentProfile, BackendPreferences
from licenselens.engine.loader import load_checks
from licenselens.models import CheckDefinition, Finding, ScanResult
from licenselens.paths import catalog_dir
from licenselens.schema_contracts import AcceptedRiskAnnotation, JsonValue, ProfileId

type JsonObject = dict[str, JsonValue]

YAML_OBJECT: Final = TypeAdapter(JsonObject)
MERGEABLE_LIST_FIELDS: Final = frozenset(
    name
    for name, field in AssessmentProfile.model_fields.items()
    if (field.json_schema_extra or {}).get("x-licenselens-mergeable") is True
)


@dataclass(frozen=True, slots=True)
class ProfileReferenceError(Exception):
    diagnostic: str

    def __str__(self) -> str:
        return self.diagnostic


@dataclass(frozen=True, slots=True)
class ProfileScalarOverrides:
    allow_proxy: bool | None = None
    allow_manual: bool | None = None
    redaction_enabled: bool | None = None


@dataclass(frozen=True, slots=True)
class ResolvedProfile:
    profile: AssessmentProfile
    profile_ids: list[str]
    selected_check_ids: list[str]


def load_builtin_profiles(root: Path | None = None) -> list[AssessmentProfile]:
    profile_root = root or catalog_dir() / "profiles"
    profiles = [
        AssessmentProfile.model_validate(
            YAML_OBJECT.validate_python(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        )
        for path in sorted(profile_root.glob("*.yaml"))
    ]
    return sorted(profiles, key=lambda profile: str(profile.id))


def compose_profile(
    builtin_profile_id: str,
    *,
    organization_profile: AssessmentProfile | None = None,
    cli_overrides: ProfileScalarOverrides | None = None,
    checks: list[CheckDefinition] | None = None,
) -> ResolvedProfile:
    builtins = {str(profile.id): profile for profile in load_builtin_profiles()}
    builtin = builtins.get(builtin_profile_id)
    if builtin is None:
        raise ProfileReferenceError(f"unknown profile: {builtin_profile_id}")

    profile = builtin
    profile_ids = [str(builtin.id)]
    if organization_profile is not None:
        profile = _overlay_profile(profile, organization_profile)
        profile_ids.append(str(organization_profile.id))
    if cli_overrides is not None:
        profile = _apply_scalar_overrides(profile, cli_overrides)

    selected = resolve_profile_checks(profile, checks or load_checks())
    return ResolvedProfile(profile=profile, profile_ids=profile_ids, selected_check_ids=selected)


def resolve_profile_checks(
    profile: AssessmentProfile,
    checks: list[CheckDefinition],
) -> list[str]:
    checks_by_id = {check.id: check for check in checks if check.enabled}
    unknown = sorted(_declared_check_ids(profile) - set(checks_by_id))
    if unknown:
        diagnostic = f"unknown check reference in profile {profile.id}: {unknown[0]}"
        raise ProfileReferenceError(diagnostic)

    selected = {
        check.id for check in checks_by_id.values() if check.pack.value in set(profile.packs)
    } | set(profile.check_ids)
    selected |= {risk.check_id for risk in profile.accepted_risks}
    return sorted(selected)


def apply_profile_to_findings(
    findings: list[Finding],
    profile: ResolvedProfile,
) -> list[Finding]:
    annotations = _risk_annotations(profile.profile)
    annotations_by_check: dict[str, list[AcceptedRiskAnnotation]] = {}
    for annotation in annotations:
        annotations_by_check.setdefault(annotation.check_id, []).append(annotation)
    return [
        finding.model_copy(
            update={
                "accepted_risks": [
                    *finding.accepted_risks,
                    *annotations_by_check.get(finding.check_id, []),
                ]
            }
        )
        for finding in findings
    ]


def apply_profile_to_scan_result(result: ScanResult, profile: ResolvedProfile) -> ScanResult:
    findings = apply_profile_to_findings(result.findings, profile)
    return result.model_copy(
        update={
            "findings": findings,
            "profile_ids": [ProfileId(profile_id) for profile_id in profile.profile_ids],
            "accepted_risks": accepted_risk_annotations(profile.profile),
        }
    )


def accepted_risk_annotations(profile: AssessmentProfile) -> list[AcceptedRiskAnnotation]:
    return _risk_annotations(profile)


def _overlay_profile(base: AssessmentProfile, overlay: AssessmentProfile) -> AssessmentProfile:
    data = base.model_dump(mode="python", exclude_computed_fields=True)
    for field_name in sorted(overlay.model_fields_set):
        if field_name in {"schema_version", "id", "name"}:
            continue
        value = getattr(overlay, field_name)
        if field_name == "backend_preferences":
            data[field_name] = _overlay_backend_preferences(base.backend_preferences, value)
        elif isinstance(value, list) and field_name in MERGEABLE_LIST_FIELDS:
            data[field_name] = [*data[field_name], *value]
        else:
            data[field_name] = value
    data["id"] = overlay.id
    data["name"] = overlay.name
    return AssessmentProfile.model_validate(data)


def _overlay_backend_preferences(
    base: BackendPreferences,
    overlay: BackendPreferences,
) -> BackendPreferences:
    data = base.model_dump(mode="python")
    for field_name in sorted(overlay.model_fields_set):
        data[field_name] = getattr(overlay, field_name)
    return BackendPreferences.model_validate(data)


def _apply_scalar_overrides(
    profile: AssessmentProfile,
    overrides: ProfileScalarOverrides,
) -> AssessmentProfile:
    backend = profile.backend_preferences.model_copy(
        update={
            key: value
            for key, value in {
                "allow_proxy": overrides.allow_proxy,
                "allow_manual": overrides.allow_manual,
            }.items()
            if value is not None
        }
    )
    redaction_update = {}
    if overrides.redaction_enabled is not None:
        redaction_update["enabled"] = overrides.redaction_enabled
    return profile.model_copy(
        update={
            "backend_preferences": backend,
            "redaction": profile.redaction.model_copy(update=redaction_update),
        }
    )


def _declared_check_ids(profile: AssessmentProfile) -> set[str]:
    return {
        *profile.check_ids,
        *(risk.check_id for risk in profile.accepted_risks),
        *(exclusion.check_id for exclusion in profile.exclusions),
    }


def _risk_annotations(profile: AssessmentProfile) -> list[AcceptedRiskAnnotation]:
    return [
        AcceptedRiskAnnotation(
            id=risk.id,
            check_id=risk.check_id,
            profile_id=profile.id,
            owner=risk.owner,
            reason=risk.reason,
            expires_on=risk.expires_on.isoformat(),
            source=risk.source,
            status=risk.status.value,
            suppresses_finding=risk.suppresses_finding,
        )
        for risk in profile.accepted_risks
    ]

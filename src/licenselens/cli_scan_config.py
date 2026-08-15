"""CLI boundary: resolve profiles, rules, backends, and report archives before auth."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml
from pydantic import ValidationError

from licenselens.config_models import (
    AssessmentProfile,
    BackendPreference,
    BackendPreferences,
    ConfigSchema,
    CustomRule,
)
from licenselens.engine.profiles import ProfileReferenceError, ResolvedProfile, compose_profile
from licenselens.models import ScanResult
from licenselens.report.bundle import ReportBundleError, build_report_bundle
from licenselens.schema_contracts import CURRENT_SCHEMA_VERSION

DEFAULT_PROFILE_WHEN_OVERRIDES: Final = "core"


@dataclass(frozen=True, slots=True)
class ScanConfigError(Exception):
    diagnostic: str

    def __str__(self) -> str:
        return self.diagnostic


def resolve_scan_profile(
    *,
    profile_id: str | None = None,
    config_path: Path | None = None,
    rules_path: Path | None = None,
    backends: list[str] | None = None,
) -> ResolvedProfile | None:
    """Compose a profile from CLI flags, or None when all flags are omitted."""
    backend_values = tuple(backends or ())
    if not any((profile_id, config_path, rules_path, backend_values)):
        return None

    base_id = (profile_id or DEFAULT_PROFILE_WHEN_OVERRIDES).strip()
    if not base_id:
        raise ScanConfigError("profile id must not be empty")

    try:
        organization = _organization_overlay(
            config_path=config_path,
            rules_path=rules_path,
            backends=backend_values,
        )
        return compose_profile(base_id, organization_profile=organization)
    except ProfileReferenceError as exc:
        raise ScanConfigError(str(exc)) from exc
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise ScanConfigError(f"invalid scan configuration: {exc}") from exc


def load_assessment_profile_file(path: Path) -> AssessmentProfile:
    if not path.is_file():
        raise ScanConfigError(f"config not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScanConfigError(f"invalid config file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScanConfigError(f"config must be a YAML mapping: {path}")
    try:
        if "profiles" in raw:
            schema = ConfigSchema.model_validate(raw)
            if len(schema.profiles) != 1:
                raise ScanConfigError(
                    f"config must contain exactly one profile when used with --config: {path}"
                )
            return schema.profiles[0]
        return AssessmentProfile.model_validate(raw)
    except ValidationError as exc:
        raise ScanConfigError(f"invalid config file {path}: {exc}") from exc


def load_custom_rules_file(path: Path) -> list[CustomRule]:
    if not path.is_file():
        raise ScanConfigError(f"rules file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScanConfigError(f"invalid rules file {path}: {exc}") from exc
    if raw is None:
        return []
    try:
        if isinstance(raw, list):
            return [CustomRule.model_validate(item) for item in raw]
        if isinstance(raw, dict) and "custom_rules" in raw:
            rules = raw["custom_rules"]
            if not isinstance(rules, list):
                raise ScanConfigError(f"custom_rules must be a list: {path}")
            return [CustomRule.model_validate(item) for item in rules]
    except ValidationError as exc:
        raise ScanConfigError(f"invalid rules file {path}: {exc}") from exc
    raise ScanConfigError(f"rules file must be a list or a mapping with custom_rules: {path}")


def parse_backend_preferences(backends: list[str]) -> list[BackendPreference]:
    parsed: list[BackendPreference] = []
    seen: set[BackendPreference] = set()
    for raw in backends:
        key = raw.strip().lower().replace("-", "_")
        try:
            backend = BackendPreference(key)
        except ValueError as exc:
            valid = ", ".join(sorted(b.value for b in BackendPreference))
            raise ScanConfigError(f"unknown backend: {raw!r} (expected one of: {valid})") from exc
        if backend in seen:
            raise ScanConfigError(f"duplicate backend preference: {backend.value}")
        seen.add(backend)
        parsed.append(backend)
    return parsed


def write_report_archive(*, output_dir: Path, result: ScanResult) -> Path:
    try:
        return build_report_bundle(result, output_dir).archive_path
    except ReportBundleError as exc:
        raise ScanConfigError(str(exc)) from exc


def _organization_overlay(
    *,
    config_path: Path | None,
    rules_path: Path | None,
    backends: tuple[str, ...],
) -> AssessmentProfile | None:
    organization: AssessmentProfile | None = None
    if config_path is not None:
        organization = load_assessment_profile_file(config_path)

    if rules_path is not None:
        rules = load_custom_rules_file(rules_path)
        if organization is None:
            organization = AssessmentProfile.model_validate(
                {
                    "schema_version": CURRENT_SCHEMA_VERSION,
                    "id": "cli-rules",
                    "name": "CLI custom rules",
                    "custom_rules": [rule.model_dump(mode="python") for rule in rules],
                }
            )
        else:
            organization = organization.model_copy(
                update={"custom_rules": [*organization.custom_rules, *rules]}
            )

    if backends:
        preferred = parse_backend_preferences(list(backends))
        preferences = BackendPreferences(
            preferred=preferred,
            allow_proxy=BackendPreference.SECURE_SCORE in preferred,
            allow_manual=True,
        )
        if organization is None:
            organization = AssessmentProfile.model_validate(
                {
                    "schema_version": CURRENT_SCHEMA_VERSION,
                    "id": "cli-backend",
                    "name": "CLI backend preferences",
                    "backend_preferences": preferences.model_dump(mode="python"),
                }
            )
        else:
            organization = organization.model_copy(update={"backend_preferences": preferences})

    return organization

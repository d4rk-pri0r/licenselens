from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import TypeAdapter, ValidationError

from licenselens.config_models import (
    AssessmentProfile,
    ConfigSchema,
    WaiverStatus,
    write_config_schema,
)
from licenselens.models import DEFAULT_PACKS

type YamlValue = str | int | float | bool | None | list["YamlValue"] | dict[str, "YamlValue"]
type YamlObject = dict[str, YamlValue]

PROFILE_DIR = Path(__file__).parents[1] / "catalog" / "profiles"
SCHEMA_PATH = PROFILE_DIR / "assessment-profile.schema.json"
YAML_OBJECT = TypeAdapter(YamlObject)


def _load_profile(path: Path) -> AssessmentProfile:
    raw = YAML_OBJECT.validate_python(yaml.safe_load(path.read_text(encoding="utf-8")))
    return AssessmentProfile.model_validate(raw)


def test_shipped_profiles_validate_when_examples_are_loaded() -> None:
    # Given: the eleven named assessment profiles shipped in catalog/profiles.
    expected_ids = {
        "core",
        "identity",
        "email",
        "collaboration",
        "endpoint",
        "data-protection",
        "secops",
        "power-platform",
        "power-bi",
        "scuba",
        "full",
    }

    # When: every YAML profile crosses the Pydantic boundary.
    profiles = [_load_profile(path) for path in sorted(PROFILE_DIR.glob("*.yaml"))]

    # Then: every required profile exists exactly once and core preserves DEFAULT_PACKS.
    profile_ids = [profile.id for profile in profiles]
    assert set(profile_ids) == expected_ids
    assert len(profile_ids) == len(set(profile_ids))
    core = next(profile for profile in profiles if profile.id == "core")
    assert core.packs == DEFAULT_PACKS


def test_expired_waiver_is_labeled_expired_and_does_not_suppress_findings() -> None:
    # Given: a profile with an accepted-risk annotation whose expiry date has passed.
    raw = {
        "schema_version": "1.0",
        "id": "core",
        "name": "Core",
        "packs": ["identity", "endpoint"],
        "accepted_risks": [
            {
                "id": "risk-expired-ca",
                "check_id": "id-ca-priv-gaps",
                "owner": "security@example.com",
                "reason": "Migration window ended.",
                "expires_on": "2000-01-01",
            }
        ],
    }

    # When: the profile is parsed at the config boundary.
    profile = AssessmentProfile.model_validate(raw)

    # Then: the waiver stays attached, is labeled expired, and cannot suppress findings.
    waiver = profile.accepted_risks[0]
    assert waiver.status is WaiverStatus.EXPIRED
    assert waiver.suppresses_finding is False


@pytest.mark.parametrize(
    ("case_name", "patch", "expected_fragment"),
    [
        ("duplicate_check_ids", {"check_ids": ["id-ca-priv-gaps", "id-ca-priv-gaps"]}, "duplicate"),
        ("unknown_profile_key", {"run_python": "print('owned')"}, "Extra inputs"),
        (
            "unknown_rule_operator",
            {
                "custom_rules": [
                    {"id": "rule-1", "selector": "finding.status", "operator": "matches"}
                ]
            },
            "operator",
        ),
        (
            "unknown_rule_selector",
            {"custom_rules": [{"id": "rule-1", "selector": "tenant.secret", "operator": "exists"}]},
            "selector",
        ),
        (
            "unsafe_reference_url",
            {
                "custom_rules": [
                    {
                        "id": "rule-1",
                        "selector": "finding.status",
                        "operator": "exists",
                        "references": ["http://evil.example/rule"],
                    }
                ]
            },
            "https",
        ),
        (
            "arbitrary_command_field",
            {
                "custom_rules": [
                    {
                        "id": "rule-1",
                        "selector": "finding.status",
                        "operator": "exists",
                        "shell": "curl evil",
                    }
                ]
            },
            "Extra inputs",
        ),
    ],
)
def test_profile_schema_fails_closed_for_unsafe_or_unknown_input(
    case_name: str,
    patch: YamlObject,
    expected_fragment: str,
) -> None:
    # Given: malicious or malformed profile input before any authentication starts.
    raw: YamlObject = {
        "schema_version": "1.0",
        "id": f"negative-{case_name}",
        "name": "Negative fixture",
        "packs": ["identity"],
    } | patch

    # When / Then: parsing fails with a deterministic detail, not misleading success.
    with pytest.raises(ValidationError) as exc_info:
        AssessmentProfile.model_validate(raw)
    assert expected_fragment in str(exc_info.value)


def test_duplicate_profile_ids_fail_before_authentication() -> None:
    # Given: two otherwise valid profiles with the same profile id.
    raw = {
        "profiles": [
            {"schema_version": "1.0", "id": "core", "name": "Core A", "packs": ["identity"]},
            {"schema_version": "1.0", "id": "core", "name": "Core B", "packs": ["endpoint"]},
        ]
    }

    # When / Then: the config collection rejects the duplicate id at schema boundary.
    with pytest.raises(ValidationError) as exc_info:
        ConfigSchema.model_validate(raw)
    assert "duplicate profile id" in str(exc_info.value)


def test_profile_json_schema_matches_generated_artifact(tmp_path: Path) -> None:
    # Given: the committed JSON Schema artifact and a fresh generation target.
    generated = tmp_path / "assessment-profile.schema.json"

    # When: schema generation runs through the public helper.
    write_config_schema(generated)

    # Then: generated schema bytes match the checked-in artifact.
    assert generated.read_text(encoding="utf-8") == SCHEMA_PATH.read_text(encoding="utf-8")

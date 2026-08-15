from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import TypeAdapter, ValidationError

from licenselens.models import (
    Confidence,
    EvaluationMode,
    Finding,
    FindingStatus,
    ScanResult,
    UnsupportedSchemaVersionError,
)

type JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "schema" / "v1"
JSON_OBJECT = TypeAdapter(JsonObject)


def _load_json(name: str) -> JsonObject:
    return JSON_OBJECT.validate_json((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def test_old_v03_json_round_trips_without_losing_existing_values() -> None:
    # Given: a v0.3 report without schema_version or additive provenance fields.
    raw = _load_json("scan-v0.3.json")

    # When: it is parsed and dumped through the public ScanResult model path.
    dumped = ScanResult.model_validate(raw).model_dump(mode="json")

    # Then: existing public values are preserved and new fields are only additive.
    assert dumped["tool"] == raw["tool"]
    assert dumped["version"] == raw["version"]
    assert dumped["tenant_display_name"] == raw["tenant_display_name"]
    assert dumped["findings"][0]["check_id"] == raw["findings"][0]["check_id"]
    assert dumped["findings"][0]["status"] == raw["findings"][0]["status"]
    assert dumped["findings"][0]["confidence"] == raw["findings"][0]["confidence"]
    assert dumped["schema_version"] == "1.0"
    assert dumped["findings"][0]["evaluation_mode"] == "direct"


def test_v1_additive_fields_parse_and_preserve_future_extras() -> None:
    # Given: a v1 report with provenance, collection, profile, risk, and future fields.
    raw = _load_json("scan-v1-additive.json")

    # When: it is parsed and dumped through the public ScanResult model path.
    result = ScanResult.model_validate(raw)
    dumped = result.model_dump(mode="json")

    # Then: new contract fields are typed and unknown additive fields survive.
    assert result.schema_version == "1.0"
    assert result.profile_ids == ["m365-foundation"]
    assert result.collection_summaries[0].status.value == "success"
    assert result.findings[0].evaluation_mode is EvaluationMode.DIRECT
    assert dumped["source_references"][0]["id"] == "graph-ca-policies"
    assert dumped["accepted_risks"][0]["id"] == "risk-ca-rollout"
    assert dumped["future_top_level_field"] == {"kept": True}
    assert dumped["findings"][0]["future_finding_field"] == {"kept": True}


@pytest.mark.parametrize(
    "mode",
    [EvaluationMode.PROXY, EvaluationMode.MANUAL, EvaluationMode.UNSUPPORTED],
)
def test_indirect_findings_reject_high_confidence_ok(mode: EvaluationMode) -> None:
    # Given: an indirect assessment attempts to claim a high-confidence ok finding.
    raw = {
        "check_id": "indirect-ok",
        "title": "Indirect ok",
        "workload": "identity",
        "status": FindingStatus.OK.value,
        "severity": "medium",
        "value_impact": "medium",
        "summary": "Indirect evidence cannot prove high-confidence ok.",
        "confidence": Confidence.HIGH.value,
        "evaluation_mode": mode.value,
    }

    # When / Then: the public Finding boundary rejects the misleading success state.
    with pytest.raises(ValidationError):
        Finding.model_validate(raw)


def test_unsupported_major_schema_version_raises_typed_error() -> None:
    # Given: a future major schema version that this reader cannot safely interpret.
    raw = _load_json("scan-v1-additive.json") | {"schema_version": "2.0"}

    # When / Then: the public ScanResult boundary raises a deterministic typed error.
    with pytest.raises(UnsupportedSchemaVersionError) as exc_info:
        ScanResult.model_validate(raw)
    assert exc_info.value.schema_version == "2.0"
    assert str(exc_info.value) == "unsupported assessment schema version: 2.0"

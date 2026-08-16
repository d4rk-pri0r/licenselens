"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

from licenselens.config_models import RedactionSettings
from licenselens.models import ScanResult
from licenselens.report.redaction import derive_redaction_targets, redact_text


def write_json_report(
    result: ScanResult,
    path: Path,
    *,
    redaction: RedactionSettings | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(result.model_dump(mode="json"), indent=2) + "\n"
    if redaction is not None:
        text = redact_text(
            text,
            targets=derive_redaction_targets(result),
            settings=redaction,
        )
    path.write_text(text, encoding="utf-8")
    return path

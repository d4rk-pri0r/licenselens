"""G1 action-plan writer (CSV/JSON) with redaction.

Builds the remediation action-plan rows via
:func:`licenselens.report.viewmodel.build_action_plan` and serializes them to a
deterministic CSV or JSON file. The serialized text is threaded through the same
redaction pipeline as the HTML/JSON/Markdown reports, so tenant ids, UPN-like
strings, and (when the settings enable it) tenant domains are stripped before
the file is written.

The CSV output is deterministic: a fixed column order, no BOM, LF line endings,
and every field escaped per RFC 4180 (commas, quotes, and newlines). The JSON
output is a plain ``json.dumps`` of the row list.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Final

from licenselens.config_models import RedactionSettings
from licenselens.models import ScanResult
from licenselens.report.redaction import derive_redaction_targets, redact_text
from licenselens.report.viewmodel import build_action_plan

#: Fixed column order for the CSV output (deterministic across runs).
_CSV_COLUMNS: Final[tuple[str, ...]] = (
    "check_id",
    "title",
    "severity",
    "effort",
    "timeline",
    "reason",
    "customer_next_step",
    "deep_link",
)


def _serialize_csv(rows: list[dict[str, object]]) -> str:
    """Serialize action-plan rows to CSV text (no BOM, escaped, LF endings)."""
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: row.get(column, "") for column in _CSV_COLUMNS})
    return buffer.getvalue()


def write_action_plan(
    result: ScanResult,
    path: Path,
    *,
    fmt: str,
    redaction: RedactionSettings | None = None,
) -> Path:
    """Write the G1 action plan to ``path`` as CSV or JSON.

    ``fmt`` is ``"csv"`` or ``"json"``. When ``redaction`` is provided the
    serialized text is redacted (tenant ids, UPN-like strings, and — when the
    settings enable it — tenant domains) before writing, using the same
    :func:`licenselens.report.redaction.redact_text` pipeline as the other
    report writers.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = build_action_plan(result)
    if fmt == "json":
        text = json.dumps(rows, indent=2) + "\n"
    else:
        text = _serialize_csv(rows)
    if redaction is not None:
        text = redact_text(
            text,
            targets=derive_redaction_targets(result),
            settings=redaction,
        )
    path.write_text(text, encoding="utf-8")
    return path


__all__ = ["write_action_plan"]

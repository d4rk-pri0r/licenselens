"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

from licenselens.models import ScanResult


def write_json_report(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    return path

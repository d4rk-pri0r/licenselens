"""Load check definitions from YAML under checks/."""

from __future__ import annotations

from pathlib import Path

import yaml

from licenselens.models import CheckDefinition, Severity, ValueImpact, Workload
from licenselens.paths import checks_dir


def load_checks(root: Path | None = None) -> list[CheckDefinition]:
    base = root or checks_dir()
    checks: list[CheckDefinition] = []
    if not base.is_dir():
        return checks

    for path in sorted(base.rglob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not raw.get("id"):
            continue
        checks.append(
            CheckDefinition(
                id=raw["id"],
                title=raw.get("title") or raw["id"],
                description=raw.get("description", ""),
                workload=Workload(raw.get("workload", "general")),
                required_capabilities=list(raw.get("required_capabilities") or []),
                severity=Severity(raw.get("severity", "medium")),
                value_impact=ValueImpact(raw.get("value_impact", "medium")),
                remediation=raw.get("remediation", ""),
                references=list(raw.get("references") or []),
                collector=raw.get("collector", "noop"),
                enabled=bool(raw.get("enabled", True)),
                source_path=str(path),
            )
        )
    return checks

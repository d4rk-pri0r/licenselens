"""Load check definitions from YAML under checks/."""

from __future__ import annotations

from pathlib import Path

import yaml

from licenselens.models import (
    BlastRadius,
    CheckDefinition,
    CheckPack,
    Effort,
    ExposureClass,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.paths import checks_dir

_REQUIRED_METADATA = (
    "impact",
    "effort",
    "blast_radius",
    "pack",
    "exposure_class",
)


def _clean(text: str | None) -> str:
    if not text:
        return ""
    return " ".join(str(text).split())


def _parse_metadata(raw: dict) -> dict:
    impact = raw.get("impact")
    if impact is None:
        # Migration: derive impact from legacy value_impact when explicit impact absent.
        impact = raw.get("value_impact", "medium")
    return {
        "impact": ValueImpact(str(impact).lower()),
        "effort": Effort(str(raw.get("effort", "hours")).lower()),
        "blast_radius": BlastRadius(str(raw.get("blast_radius", "all_users")).lower()),
        "pack": CheckPack(str(raw.get("pack", "starter")).lower()),
        "exposure_class": ExposureClass(str(raw.get("exposure_class", "none")).lower()),
        "deep_link": raw.get("deep_link"),
    }


def _validate_required_metadata(raw: dict, path: Path) -> None:
    missing = [key for key in _REQUIRED_METADATA if key not in raw or raw.get(key) in (None, "")]
    if missing:
        raise ValueError(
            f"Check {raw.get('id', '?')!r} at {path} is missing required metadata: "
            + ", ".join(missing)
            + ". Add impact/effort/blast_radius/pack/exposure_class to the YAML."
        )


def load_checks(root: Path | None = None) -> list[CheckDefinition]:
    base = root or checks_dir()
    checks: list[CheckDefinition] = []
    if not base.is_dir():
        return checks

    for path in sorted(base.rglob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not raw.get("id"):
            continue
        if raw.get("enabled", True):
            _validate_required_metadata(raw, path)
        meta = _parse_metadata(raw)
        checks.append(
            CheckDefinition(
                id=raw["id"],
                title=raw.get("title") or raw["id"],
                description=_clean(raw.get("description")),
                workload=Workload(raw.get("workload", "general")),
                required_capabilities=list(raw.get("required_capabilities") or []),
                severity=Severity(raw.get("severity", "medium")),
                value_impact=ValueImpact(raw.get("value_impact", "medium")),
                impact=meta["impact"],
                effort=meta["effort"],
                blast_radius=meta["blast_radius"],
                pack=meta["pack"],
                exposure_class=meta["exposure_class"],
                deep_link=meta["deep_link"],
                remediation=_clean(raw.get("remediation")),
                references=list(raw.get("references") or []),
                collector=raw.get("collector", "noop"),
                enabled=bool(raw.get("enabled", True)),
                customer_title=_clean(raw.get("customer_title")),
                customer_summary=_clean(raw.get("customer_summary")),
                expected_state=_clean(raw.get("expected_state")),
                customer_next_step=_clean(raw.get("customer_next_step")),
                source_path=str(path),
            )
        )
    return checks

#!/usr/bin/env python3
"""Deterministically regenerate reference documentation and the sanitized sample.

This script is the single consumer of the todo-5 reference model
(``licenselens.catalog.reference.build_reference_model``) and emits, from that
model and from a pinned dry-run fixture, two committed artifact families:

* ``docs/reference/*`` — check, capability, profile, permission, and coverage
  reference pages plus a machine-readable ``reference.json`` and a
  ``manifest.json`` source map. Every check's state/backend/permission/license/
  source and every coverage gap are disclosed; nothing carries a tenant
  identifier or a secret.
* ``examples/sample-report/security-license-lens-report.json`` — the sanitized
  sample scan artifact, byte-reproducible from a pinned timestamp.

Determinism: every collection is sorted before rendering, JSON uses
``sort_keys=True``, and the sample timestamp is frozen, so two runs produce
identical bytes.

Freshness: ``--check`` regenerates everything and compares it byte-for-byte
against the committed files, and additionally fails when the sample's ``version``
field differs from ``licenselens.__version__``. Any source-catalog change that
was not followed by a regeneration, any manual edit to a generated file, and any
sample/package version skew therefore surfaces as a non-zero exit.

Run:  uv run python scripts/generate_reference_docs.py [--check]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from licenselens import __version__
from licenselens.auth import AuthMode, build_auth_context
from licenselens.catalog._reference_models import ReferenceModelPaths
from licenselens.catalog.reference import ReferenceModel, build_reference_model
from licenselens.engine.runner import run_scan
from licenselens.models import ScanResult

REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCE_DIR = Path("docs") / "reference"
SAMPLE_JSON_PATH = Path("examples") / "sample-report" / "security-license-lens-report.json"

# Frozen scan timestamp so the sample bundle is byte-reproducible across runs.
SAMPLE_SCANNED_AT: Final = "2026-08-13T00:00:00+00:00"
ZERO_TENANT_ID: Final = "00000000-0000-0000-0000-000000000000"
SAMPLE_DISPLAY_NAME: Final = "Demo (synthetic data)"

GENERATOR_NAME: Final = "scripts/generate_reference_docs.py"

# ScuBA dispositions that LicenseLens tracks but does not automate.
COVERAGE_GAP_STATES: Final = frozenset({"manual", "unsupported", "not_applicable"})

SECRET_TOKENS: Final = (
    "client_secret",
    "clientsecret",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "api_key",
    "apikey",
    "authorization: bearer",
    "authorization: basic",
)


@dataclass(frozen=True, slots=True)
class Generation:
    """Everything the generator produces, held in memory before writing."""

    package_version: str
    sample_version: str
    reference_files: dict[str, str]
    sample_json: str
    sources: dict[str, str]


def build_generation(paths: ReferenceModelPaths | None = None) -> Generation:
    """Build the reference model, render pages, and produce the sanitized sample."""
    model = build_reference_model(paths)
    sample = _build_sample_result()
    sample_json = _serialize_sample(sample)
    problems = [*find_secrets(sample_json), *verify_sanitized(sample_json)]
    if problems:
        raise RuntimeError("sanitized sample carries secrets/identifiers: " + ", ".join(problems))
    sample_version = str(json.loads(sample_json)["version"])
    sources = _source_map(paths or _default_paths())
    reference_files = _render_reference_files(model)
    reference_files["manifest.json"] = _render_manifest(
        model, reference_files, sample_version, sample_json, sources
    )
    return Generation(
        package_version=__version__,
        sample_version=sample_version,
        reference_files=reference_files,
        sample_json=sample_json,
        sources=sources,
    )


def write_generation(gen: Generation, root: Path = REPO_ROOT) -> list[Path]:
    """Write all generated artifacts under ``root`` and return their paths."""
    written: list[Path] = []
    for relative, content in gen.reference_files.items():
        target = root / REFERENCE_DIR / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written.append(target)
    sample_target = root / SAMPLE_JSON_PATH
    sample_target.parent.mkdir(parents=True, exist_ok=True)
    sample_target.write_text(gen.sample_json, encoding="utf-8")
    written.append(sample_target)
    return written


def check_generation(gen: Generation, root: Path = REPO_ROOT) -> list[str]:
    """Return drift/consistency problems; an empty list means the tree is fresh."""
    problems: list[str] = []
    for relative, content in sorted(gen.reference_files.items()):
        target = root / REFERENCE_DIR / relative
        if not target.is_file():
            problems.append(f"missing_generated_file:{relative}")
            continue
        if target.read_text(encoding="utf-8") != content:
            problems.append(f"generated_file_drift:{relative}")
    sample_target = root / SAMPLE_JSON_PATH
    if not sample_target.is_file():
        problems.append(f"missing_generated_file:{SAMPLE_JSON_PATH.as_posix()}")
    else:
        committed = sample_target.read_text(encoding="utf-8")
        if committed != gen.sample_json:
            problems.append(f"generated_file_drift:{SAMPLE_JSON_PATH.as_posix()}")
        problems.extend(f"sample_secret:{token}" for token in find_secrets(committed))
        problems.extend(f"sample_unsanitized:{reason}" for reason in verify_sanitized(committed))
        try:
            committed_version = json.loads(committed)["version"]
        except (json.JSONDecodeError, KeyError, TypeError):
            problems.append("sample_version_missing")
        else:
            if committed_version != gen.package_version:
                problems.append(
                    f"sample_version_mismatch:{committed_version}!={gen.package_version}"
                )
    return problems


def find_secrets(text: str) -> list[str]:
    """Return secret detections in ``text`` (empty means no credentials leak)."""
    lowered = text.lower()
    return [f"secret:{token}" for token in SECRET_TOKENS if token in lowered]


def verify_sanitized(sample_json: str) -> list[str]:
    """Return tenant-identifier leaks in the sample JSON (empty means sanitized)."""
    problems: list[str] = []
    try:
        data = json.loads(sample_json)
    except (json.JSONDecodeError, TypeError):
        return ["sample_invalid_json"]
    if data.get("tenant_id") != ZERO_TENANT_ID:
        problems.append(f"tenant_identifier:{data.get('tenant_id')}")
    if data.get("tenant_display_name") != SAMPLE_DISPLAY_NAME:
        problems.append(f"tenant_display_name:{data.get('tenant_display_name')}")
    if data.get("tenant_slug") is not None:
        problems.append("tenant_slug_present")
    if data.get("workspace_resource_id") is not None:
        problems.append("workspace_resource_id_present")
    return problems


def _default_paths() -> ReferenceModelPaths:
    from licenselens.paths import catalog_dir, checks_dir

    catalog_root = catalog_dir()
    return ReferenceModelPaths(
        capabilities_path=catalog_root / "capabilities.yaml",
        checks_root=checks_dir(),
        profiles_root=catalog_root / "profiles",
        coverage_path=catalog_root / "coverage" / "scuba-2026-08.yaml",
        permission_docs_path=catalog_root.parent / "docs" / "permissions.md",
    )


def _build_sample_result() -> ScanResult:
    """Run the offline dry-run scan and return a sanitized result."""
    auth = build_auth_context(mode=AuthMode.DRY_RUN)
    scanned_at = datetime.fromisoformat(SAMPLE_SCANNED_AT)
    return sanitize_sample_result(run_scan(auth, dry_run=True, scanned_at=scanned_at))


def sanitize_sample_result(result: ScanResult) -> ScanResult:
    """Pin the timestamp and overwrite any tenant identifier with synthetic values."""
    result.scanned_at = SAMPLE_SCANNED_AT
    result.tenant_id = ZERO_TENANT_ID
    result.tenant_display_name = SAMPLE_DISPLAY_NAME
    result.tenant_slug = None
    result.workspace_resource_id = None
    return result


def _serialize_sample(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2) + "\n"


def _source_map(paths: ReferenceModelPaths) -> dict[str, str]:
    files = {paths.capabilities_path, paths.coverage_path, paths.permission_docs_path}
    files.update(paths.checks_root.rglob("*.yaml"))
    files.update(paths.profiles_root.rglob("*.yaml"))
    return {str(path.relative_to(REPO_ROOT)): _sha256(path.read_bytes()) for path in sorted(files)}


def _render_reference_files(model: ReferenceModel) -> dict[str, str]:
    return {
        "index.md": _render_index(model),
        "checks.md": _render_checks(model),
        "capabilities.md": _render_capabilities(model),
        "profiles.md": _render_profiles(model),
        "permissions.md": _render_permissions(model),
        "coverage.md": _render_coverage(model),
        "reference.json": _dump_reference_json(model),
    }


def _render_manifest(
    model: ReferenceModel,
    pages: dict[str, str],
    sample_version: str,
    sample_json: str,
    sources: dict[str, str],
) -> str:
    generated = {
        relative: _sha256(content.encode("utf-8")) for relative, content in sorted(pages.items())
    }
    payload = {
        "generator": GENERATOR_NAME,
        "package_version": __version__,
        "sample_version": sample_version,
        "sample_sha256": _sha256(sample_json.encode("utf-8")),
        "coverage_source": "catalog/coverage/scuba-2026-08.yaml",
        "check_count": len(model.checks),
        "capability_count": len(model.capabilities),
        "profile_count": len(model.profiles),
        "permission_count": len(model.graph_permissions),
        "coverage_row_count": len(model.coverage_rows),
        "untracked_row_count": len(model.untracked_coverage_rows),
        "baseline_row_total": len(model.coverage_rows) + len(model.untracked_coverage_rows),
        "coverage_gap_count": sum(
            row.disposition.value in COVERAGE_GAP_STATES for row in model.coverage_rows
        ),
        "sources": sources,
        "generated": generated,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _render_index(model: ReferenceModel) -> str:
    gap_count = sum(row.disposition.value in COVERAGE_GAP_STATES for row in model.coverage_rows)
    lines = [
        _banner(),
        "# Reference",
        "",
        f"Machine-generated from the todo-5 reference model (package version **{__version__}**).",
        "",
        "| Artifact | Count |",
        "|----------|------:|",
        f"| [Checks](checks.md) | {len(model.checks)} |",
        f"| [Capabilities](capabilities.md) | {len(model.capabilities)} |",
        f"| [Profiles](profiles.md) | {len(model.profiles)} |",
        f"| [Graph permissions](permissions.md) | {len(model.graph_permissions)} |",
        f"| [Coverage rows](coverage.md) | {len(model.coverage_rows)} |",
        f"| [Untracked baseline rows](coverage.md) | {len(model.untracked_coverage_rows)} |",
        f"| Coverage gaps (manual/unsupported/not-applicable) | {gap_count} |",
        "",
        "## Provenance",
        "",
        f"- Generator: `{GENERATOR_NAME}`",
        "- Source model: `licenselens.catalog.reference.build_reference_model`",
        "- Machine-readable: `reference.json` (published alongside this page)",
        "- Source map: `manifest.json` (source and generated content hashes)",
        "",
        "These pages are deterministic and are regenerated by CI; manual edits are",
        "detected and fail the freshness check.",
        "",
    ]
    return "\n".join(lines)


def _dump_reference_json(model: ReferenceModel) -> str:
    """Serialize the reference model with machine-independent check source paths."""
    data = model.model_dump(mode="json")
    for check in data.get("checks", []):
        source = check.get("source_path")
        if source:
            check["source_path"] = _source_label(str(source))
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def _source_label(path: str) -> str:
    normalized = path.replace("\\", "/")
    marker = "/checks/"
    index = normalized.rfind(marker)
    return normalized[index + 1 :] if index != -1 else normalized


def _render_checks(model: ReferenceModel) -> str:
    lines = [
        _banner(),
        "# Check reference",
        "",
        f"{len(model.checks)} checks. Every check discloses its collector (backend),",
        "support state (direct, proxy, manual, unsupported, or",
        "direct_with_proxy_fallback), evaluator registration, required",
        "capabilities, evidence keys, and source file.",
        "",
        "| Check ID | Collector (backend) | State | Evaluator | Required capabilities |"
        " Evidence keys | Source |",
        "|----------|---------------------|-------|-----------|-----------------------|"
        "---------------|--------|",
    ]
    for check in model.checks:
        lines.append(
            "| `{id}` | `{collector}` | {state} | {evaluator} | {caps} | {evidence} |"
            " `{source}` |".format(
                id=check.id,
                collector=check.collector,
                state=_cell(check.support_state.value),
                evaluator=_cell("registered" if check.evaluator_registered else "missing"),
                caps=_cell(", ".join(check.required_capabilities) or "—"),
                evidence=_cell(", ".join(check.evidence_keys) or "—"),
                source=_cell(_source_label(check.source_path) if check.source_path else "—"),
            )
        )
    lines += [
        "",
        "**State** comes from the runtime registry evaluation mode:",
        "`direct` (Graph/ARM/bridge), `proxy` (Secure Score proxy), `manual`",
        "(operator-confirmed), `unsupported` (no automated path), or",
        "`direct_with_proxy_fallback` (direct evidence first, Secure Score only when",
        "direct is unavailable). Per-finding report rows still serialize the observed",
        "mode (`direct` or `proxy`) when a dynamic check runs. `missing` under",
        "Evaluator would be rejected by the reference model, so it cannot appear here.",
        "",
    ]
    return "\n".join(lines)


def _render_capabilities(model: ReferenceModel) -> str:
    lines = [
        _banner(),
        "# Capability reference",
        "",
        f"{len(model.capabilities)} capabilities. Each discloses its workloads,",
        "entitlement kind, backends, clouds, SKU part numbers, service plans, the",
        "checks it gates, and its catalog source version.",
        "",
        "| Capability | Workloads | Kind | Backends | Clouds | SKUs | Service plans |"
        " Required by | Source version |",
        "|------------|-----------|------|----------|--------|------|---------------|"
        "-------------|----------------|",
    ]
    for cap in model.capabilities:
        lines.append(
            "| `{id}` | {workloads} | `{kind}` | {backends} | {clouds} | {skus} |"
            " {plans} | {checks} | `{source}` |".format(
                id=cap.id,
                workloads=_cell(", ".join(cap.workloads) or "—"),
                kind=_cell(cap.entitlement_kind),
                backends=_cell(", ".join(cap.backends) or "—"),
                clouds=_cell(", ".join(cap.clouds) or "—"),
                skus=_cell(", ".join(cap.sku_part_numbers) or "—"),
                plans=_cell(", ".join(cap.service_plan_names) or "—"),
                checks=_cell(", ".join(cap.required_by_checks) or "—"),
                source=_cell(cap.source_version or "—"),
            )
        )
    lines += [
        "",
        "`docs_url` values are disclosed in `reference.json` (``docs_url`` field per",
        "capability) to keep this table readable.",
        "",
    ]
    return "\n".join(lines)


def _render_profiles(model: ReferenceModel) -> str:
    lines = [
        _banner(),
        "# Profile reference",
        "",
        f"{len(model.profiles)} assessment profiles. Each discloses its packs, its",
        "explicitly declared check ids, and the resolved check set (declared plus",
        "pack-expanded).",
        "",
        "| Profile | Packs | Declared | Resolved checks |",
        "|---------|-------|---------:|-----------------|",
    ]
    for profile in model.profiles:
        lines.append(
            "| `{id}` | {packs} | {declared} | {resolved} |".format(
                id=profile.id,
                packs=_cell(", ".join(profile.packs) or "—"),
                declared=len(profile.check_ids),
                resolved=_cell(", ".join(profile.resolved_check_ids) or "—"),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _render_permissions(model: ReferenceModel) -> str:
    lines = [
        _banner(),
        "# Permission reference",
        "",
        f"{len(model.graph_permissions)} Microsoft Graph application permissions are",
        "required. All are read-only (`*.Read.All` / `*.Read.Directory`); LicenseLens",
        "never grants write access.",
        "",
        "| Permission |",
        "|------------|",
    ]
    for permission in model.graph_permissions:
        lines.append(f"| `{_cell(permission)}` |")
    lines += [
        "",
        "## PowerShell bridge modules",
        "",
        "Exchange Online, Teams, SharePoint, and Power Platform surfaces are collected",
        "through the allowlisted PowerShell bridge using official modules only:",
        "",
    ]
    for module in model.permission_modules:
        lines.append(f"- `{_cell(module)}`")
    lines += [
        "",
        "The authoritative per-operation matrix lives in `src/licenselens/graph_ops.py`",
        "and the purpose of each permission in [permissions.md](../permissions.md).",
        "",
    ]
    return "\n".join(lines)


def _render_coverage(model: ReferenceModel) -> str:
    gap_count = sum(row.disposition.value in COVERAGE_GAP_STATES for row in model.coverage_rows)
    untracked = model.untracked_coverage_rows
    accounted = len(model.coverage_rows) + len(untracked)
    lines = [
        _banner(),
        "# Coverage reference",
        "",
        f"{len(model.coverage_rows)} SCuBA policy rows are mapped; "
        f"{len(untracked)} are explicitly untracked. "
        f"All {accounted} baseline rows at the pinned commit are accounted for.",
        f"{gap_count} of the mapped rows are coverage gaps: tracked but not automated",
        "by LicenseLens.",
        "",
        "| Policy ID | Product | Disposition | Local checks | Source |",
        "|-----------|---------|-------------|--------------|--------|",
    ]
    for row in model.coverage_rows:
        lines.append(
            "| `{policy}` | `{product}` | `{disposition}` | {checks} | `{source}` |".format(
                policy=row.policy_id,
                product=row.product,
                disposition=row.disposition.value,
                checks=_cell(", ".join(row.local_check_ids) or "—"),
                source=_cell(row.source_path or "—"),
            )
        )
    lines += [
        "",
        "## Coverage gaps",
        "",
        f"The following {gap_count} policies are tracked but not automated. They",
        "disclose the SCuBA source path so the gap is auditable.",
        "",
    ]
    for row in model.coverage_rows:
        if row.disposition.value in COVERAGE_GAP_STATES:
            lines.append(f"- `{row.policy_id}` ({row.product}, {row.disposition.value})")
    lines += [
        "",
        "`implemented_direct` rows map to direct Graph/ARM/bridge evaluation and",
        "`implemented_proxy` rows to Secure Score proxy checks; both carry their local",
        "check ids and pinned SCuBA source path.",
        "",
    ]
    if untracked:
        lines += [
            "## Explicitly untracked baseline rows",
            "",
            f"The following {len(untracked)} baseline rows are explicitly untracked:",
            "superseded or removed upstream, with the disposition recorded.",
            "",
            "| Policy ID | Product | Rationale | Source |",
            "|-----------|---------|-----------|--------|",
        ]
        for row in untracked:
            lines.append(
                "| `{policy}` | `{product}` | {rationale} | `{source}` |".format(
                    policy=row.policy_id,
                    product=row.product,
                    rationale=_cell(row.rationale),
                    source=_cell(row.source_path or "—"),
                )
            )
        lines.append("")
    return "\n".join(lines)


def _banner() -> str:
    return (
        "<!-- GENERATED by scripts/generate_reference_docs.py — DO NOT EDIT by hand. "
        "Regenerate with: uv run python scripts/generate_reference_docs.py -->"
    )


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Regenerate reference docs and sample.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate and compare against committed files; fail on drift",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repository root to write/check against (default: repo root)",
    )
    args = parser.parse_args(argv)

    try:
        generation = build_generation()
    except Exception as exc:  # noqa: BLE001 - surface any catalog error clearly
        print(f"FAIL: generator could not build the reference artifacts: {exc}")
        return 2

    if args.check:
        problems = check_generation(generation, args.root)
        for problem in problems:
            print(f"FAIL: {problem}")
        if problems:
            print(f"FAIL: {len(problems)} drift/consistency problem(s)")
            return 1
        print(
            "PASS: reference docs and sample bundle are fresh "
            f"(package {generation.package_version}, sample {generation.sample_version})"
        )
        return 0

    written = write_generation(generation, args.root)
    for path in written:
        print(f"wrote {path.relative_to(args.root)}")
    print(f"package_version={generation.package_version}")
    print(f"sample_version={generation.sample_version}")
    print(f"source_files={len(generation.sources)}")
    print("PASS: reference docs and sample bundle regenerated deterministically")
    return 0


if __name__ == "__main__":
    sys.exit(main())

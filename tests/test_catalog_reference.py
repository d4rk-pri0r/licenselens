from __future__ import annotations

from collections.abc import MutableMapping
from pathlib import Path

import pytest
import yaml

from licenselens.catalog.reference import (
    ReferenceCatalogError,
    ReferenceModelPaths,
    build_reference_model,
    dump_reference_json,
)

ROOT = Path(__file__).resolve().parents[1]


def test_reference_model_includes_current_catalog_and_is_deterministic() -> None:
    # Given: the shipped catalog, checks, profiles, permission docs, and SCuBA manifest.
    # When: the reference model is built and serialized twice.
    model = build_reference_model()
    first = dump_reference_json(model)
    second = dump_reference_json(build_reference_model())

    # Then: every current source row is represented in stable byte-identical output.
    assert first == second
    assert len(model.checks) >= 50
    assert len(model.capabilities) >= 8
    assert {cap.id for cap in model.capabilities} >= {
        "entra_id_p2",
        "exchange_online",
        "teams",
        "intune",
        "defender_xdr",
        "purview_audit",
        "defender_for_cloud_cspm",
    }
    assert all(cap.source_version for cap in model.capabilities)
    assert all(cap.entitlement_kind for cap in model.capabilities)
    assert len(model.profiles) == 11
    assert len(model.graph_permissions) >= 15
    assert "Domain.Read.All" in model.graph_permissions
    assert len(model.coverage_rows) == 109
    assert [check.id for check in model.checks] == sorted(check.id for check in model.checks)
    assert {check.support_state for check in model.checks} <= {
        "direct",
        "proxy",
        "manual",
        "unsupported",
        "direct_with_proxy_fallback",
    }
    assert "direct" in {check.support_state for check in model.checks}
    assert "manual" in {check.support_state for check in model.checks}
    assert "direct_with_proxy_fallback" in {check.support_state for check in model.checks}
    assert any(check.id.startswith("id-ca-") for check in model.checks)


def test_reference_model_rejects_capability_without_checks(tmp_path: Path) -> None:
    # Given: a copied source tree with one unused capability (orphan mapping).
    paths = _copy_reference_inputs(tmp_path)
    capability_data = yaml.safe_load(paths.capabilities_path.read_text(encoding="utf-8"))
    capability_data["capabilities"].append(
        {
            "id": "unused_capability",
            "name": "Unused",
            "workloads": ["identity"],
            "entitlement_kind": "base",
            "source_version": "2026-08",
        }
    )
    paths.capabilities_path.write_text(yaml.safe_dump(capability_data), encoding="utf-8")

    # When / Then: empty required_by_checks fails closed (AF-D).
    with pytest.raises(ReferenceCatalogError) as exc_info:
        build_reference_model(paths)
    assert "empty_required_by_checks:unused_capability" in exc_info.value.diagnostics


def test_reference_model_rejects_unknown_capability_on_check(tmp_path: Path) -> None:
    # Given: a check requiring a capability missing from the catalog.
    paths = _copy_reference_inputs(tmp_path)
    check_path = paths.checks_root / "identity" / "id-ca-priv-gaps.yaml"
    check_data = yaml.safe_load(check_path.read_text(encoding="utf-8"))
    check_data["required_capabilities"] = ["missing_capability"]
    check_path.write_text(yaml.safe_dump(check_data), encoding="utf-8")

    # When / Then: unknown capability references fail closed.
    with pytest.raises(ReferenceCatalogError) as exc_info:
        build_reference_model(paths)
    assert "unknown_capability:id-ca-priv-gaps:missing_capability" in exc_info.value.diagnostics


def test_reference_model_rejects_profile_drift(tmp_path: Path) -> None:
    # Given: profiles that reference an unknown check and a pack with no resolvable checks.
    paths = _copy_reference_inputs(tmp_path)
    profile_path = paths.profiles_root / "identity.yaml"
    profile_data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    profile_data["check_ids"] = ["id-ca-priv-gaps", "missing-check"]
    profile_path.write_text(yaml.safe_dump(profile_data), encoding="utf-8")
    for check_path in paths.checks_root.rglob("*.yaml"):
        check_data = yaml.safe_load(check_path.read_text(encoding="utf-8"))
        if check_data.get("pack") == "starter":
            check_data["pack"] = "identity"
            check_path.write_text(yaml.safe_dump(check_data), encoding="utf-8")
    (paths.profiles_root / "empty.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "id": "empty",
                "name": "Empty",
                "packs": ["starter"],
            }
        ),
        encoding="utf-8",
    )

    # When / Then: profile drift fails before any runtime behavior can claim success.
    with pytest.raises(ReferenceCatalogError) as exc_info:
        build_reference_model(paths)
    assert "unknown_profile_check:identity:missing-check" in exc_info.value.diagnostics
    assert "empty_profile_pack:empty:starter" in exc_info.value.diagnostics


def test_reference_model_rejects_permission_drift(tmp_path: Path) -> None:
    # Given: permission documentation missing one required Graph application permission.
    paths = _copy_reference_inputs(tmp_path)
    text = paths.permission_docs_path.read_text(encoding="utf-8")
    policy_row = (
        "| `Policy.Read.All` | Conditional Access, named locations, auth methods, cross-tenant |\n"
    )
    paths.permission_docs_path.write_text(text.replace(policy_row, ""), encoding="utf-8")

    # When / Then: the permission tuple cannot drift from docs silently.
    with pytest.raises(ReferenceCatalogError) as exc_info:
        build_reference_model(paths)
    assert "undocumented_permission:Policy.Read.All" in exc_info.value.diagnostics


def test_reference_model_rejects_missing_runtime_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: current check YAML with runtime registry missing evaluator/evidence for checks.
    import licenselens.catalog.reference as reference
    from licenselens.engine.registry import AssessmentRegistry, default_registry

    paths = _copy_reference_inputs(tmp_path)
    registry = default_registry()
    evaluators = dict(registry.evaluators)
    del evaluators["id-ca-priv-gaps"]
    stripped = evaluators["id-idprotect-off"]
    from dataclasses import replace

    evaluators["id-idprotect-off"] = replace(stripped, input_models=())
    slim = AssessmentRegistry(
        data_sources=registry.data_sources,
        collectors=registry.collectors,
        evaluators=evaluators,
    )
    monkeypatch.setattr(reference, "default_registry", lambda: slim)

    # When / Then: runtime registry drift is reported as typed diagnostics.
    with pytest.raises(ReferenceCatalogError) as exc_info:
        build_reference_model(paths)
    assert "missing_evaluator:id-ca-priv-gaps" in exc_info.value.diagnostics
    assert "orphan_check:id-ca-priv-gaps" in exc_info.value.diagnostics
    assert "missing_evidence_keys:id-idprotect-off" in exc_info.value.diagnostics


def test_reference_model_rejects_contradictory_coverage_rows(tmp_path: Path) -> None:
    # Given: coverage rows with unknown source path, unknown check id, and manual claimed coverage.
    paths = _copy_reference_inputs(tmp_path)
    data = _coverage_data(paths)
    rows = data["policies"]
    rows[0]["product"] = "unknown"
    rows[1]["local_check_ids"] = ["missing-check"]
    rows[1]["disposition"] = "implemented_direct"
    rows[2]["local_check_ids"] = ["id-ca-priv-gaps"]
    rows[2]["disposition"] = "manual"
    paths.coverage_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    # When / Then: every unsupported state transition is exposed as a typed diagnostic.
    with pytest.raises(ReferenceCatalogError) as exc_info:
        build_reference_model(paths)
    assert "unresolved_coverage_path:0:unknown" in exc_info.value.diagnostics
    assert "unknown_coverage_check:MS.AAD.2.1v1:missing-check" in exc_info.value.diagnostics
    assert "contradictory_coverage_state:MS.AAD.2.2v1:manual" in exc_info.value.diagnostics


def test_reference_model_rejects_direct_proxy_coverage_contradictions(
    tmp_path: Path,
) -> None:
    # Given: implemented coverage rows whose disposition disagrees with check support state.
    paths = _copy_reference_inputs(tmp_path)
    data = _coverage_data(paths)
    rows = data["policies"]
    rows[0]["local_check_ids"] = ["mdo-p2-policies-default"]
    rows[0]["disposition"] = "implemented_direct"
    rows[1]["local_check_ids"] = ["id-ca-priv-gaps"]
    rows[1]["disposition"] = "implemented_proxy"
    paths.coverage_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    # When / Then: proxy-as-direct and direct-as-proxy claims fail closed.
    with pytest.raises(ReferenceCatalogError) as exc_info:
        build_reference_model(paths)
    assert "contradictory_coverage_state:MS.AAD.1.1v1:implemented_direct" in (
        exc_info.value.diagnostics
    )
    assert "contradictory_coverage_state:MS.AAD.2.1v1:implemented_proxy" in (
        exc_info.value.diagnostics
    )


def test_reference_model_rejects_tracked_noncoverage_rows_with_check_ids(
    tmp_path: Path,
) -> None:
    # Given: tracked manual, unsupported, and not-applicable rows that claim local checks.
    paths = _copy_reference_inputs(tmp_path)
    data = _coverage_data(paths)
    rows = data["policies"]
    rows[0]["local_check_ids"] = ["id-ca-priv-gaps"]
    rows[0]["disposition"] = "unsupported"
    rows[1]["local_check_ids"] = ["id-idprotect-off"]
    rows[1]["disposition"] = "not_applicable"
    rows[2]["local_check_ids"] = ["id-pim-unused"]
    rows[2]["disposition"] = "manual"
    paths.coverage_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    # When / Then: tracked noncoverage states cannot be converted into check coverage.
    with pytest.raises(ReferenceCatalogError) as exc_info:
        build_reference_model(paths)
    assert "contradictory_coverage_state:MS.AAD.1.1v1:unsupported" in (exc_info.value.diagnostics)
    assert "contradictory_coverage_state:MS.AAD.2.1v1:not_applicable" in (
        exc_info.value.diagnostics
    )
    assert "contradictory_coverage_state:MS.AAD.2.2v1:manual" in exc_info.value.diagnostics


def _copy_reference_inputs(tmp_path: Path) -> ReferenceModelPaths:
    catalog_root = tmp_path / "catalog"
    checks_root = tmp_path / "checks"
    profiles_root = catalog_root / "profiles"
    coverage_root = catalog_root / "coverage"
    docs_root = tmp_path / "docs"
    checks_root.mkdir(parents=True)
    profiles_root.mkdir(parents=True)
    coverage_root.mkdir(parents=True)
    docs_root.mkdir(parents=True)
    _copy_tree(ROOT / "checks", checks_root)
    _copy_tree(ROOT / "catalog" / "profiles", profiles_root)
    (catalog_root / "capabilities.yaml").write_text(
        (ROOT / "catalog" / "capabilities.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (coverage_root / "scuba-2026-08.yaml").write_text(
        (ROOT / "catalog" / "coverage" / "scuba-2026-08.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (docs_root / "permissions.md").write_text(
        (ROOT / "docs" / "permissions.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return ReferenceModelPaths(
        capabilities_path=catalog_root / "capabilities.yaml",
        checks_root=checks_root,
        profiles_root=profiles_root,
        coverage_path=coverage_root / "scuba-2026-08.yaml",
        permission_docs_path=docs_root / "permissions.md",
    )


def _copy_tree(source: Path, target: Path) -> None:
    for path in sorted(source.rglob("*.yaml")):
        relative = path.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def _coverage_data(
    paths: ReferenceModelPaths,
) -> MutableMapping[str, list[MutableMapping[str, str]]]:
    data = yaml.safe_load(paths.coverage_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    rows = data.get("policies")
    assert isinstance(rows, list)
    return data

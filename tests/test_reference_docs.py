"""Tests for the reference-docs generator (todo 30)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from licenselens.catalog.reference import ReferenceCatalogError, build_reference_model
from licenselens.models import ScanResult

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "scripts" / "generate_reference_docs.py"

ZERO_TENANT_ID = "00000000-0000-0000-0000-000000000000"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("generate_reference_docs", GENERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["generate_reference_docs"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen(mod):
    return mod.build_generation()


def test_reference_docs_are_deterministic(mod) -> None:
    first = mod.build_generation()
    second = mod.build_generation()

    assert first.reference_files == second.reference_files
    assert first.sample_json == second.sample_json
    assert first.sources == second.sources
    assert first.package_version == first.sample_version


def test_reference_docs_stable_across_wall_clock_rollover(mod, monkeypatch) -> None:
    import datetime as _dt

    import licenselens.engine.runner as runner

    class _FrozenDatetime:
        def __init__(self, frozen: _dt.datetime) -> None:
            self._frozen = frozen

        def now(self, tz: _dt.tzinfo | None = None) -> _dt.datetime:
            return self._frozen

    monkeypatch.setattr(
        runner, "datetime", _FrozenDatetime(_dt.datetime(2099, 1, 1, tzinfo=_dt.UTC))
    )
    first = mod.build_generation()

    monkeypatch.setattr(
        runner, "datetime", _FrozenDatetime(_dt.datetime(2020, 6, 15, tzinfo=_dt.UTC))
    )
    second = mod.build_generation()

    assert first.sample_json == second.sample_json
    assert first.reference_files == second.reference_files


def test_reference_docs_disclose_everything(mod, gen) -> None:
    model = build_reference_model()

    checks = gen.reference_files["checks.md"]
    capabilities = gen.reference_files["capabilities.md"]
    profiles = gen.reference_files["profiles.md"]
    permissions = gen.reference_files["permissions.md"]
    coverage = gen.reference_files["coverage.md"]

    for check in model.checks:
        assert f"`{check.id}`" in checks
        assert check.collector in checks
        assert check.support_state.value in checks
        source = mod._source_label(check.source_path) if check.source_path else "—"
        assert source in checks
    for cap in model.capabilities:
        assert f"`{cap.id}`" in capabilities
        assert cap.entitlement_kind in capabilities
        assert cap.source_version in capabilities
    for profile in model.profiles:
        assert f"`{profile.id}`" in profiles
    for permission in model.graph_permissions:
        assert f"`{permission}`" in permissions
    for row in model.coverage_rows:
        assert f"`{row.policy_id}`" in coverage
        assert row.disposition.value in coverage
    assert "Coverage gaps" in coverage


def test_reference_docs_have_no_secrets_or_tenant_identifiers(mod, gen) -> None:
    assert mod.find_secrets(gen.sample_json) == []
    assert mod.verify_sanitized(gen.sample_json) == []
    for relative, content in gen.reference_files.items():
        if relative.endswith(".json"):
            assert mod.find_secrets(content) == [], relative


def test_sample_version_matches_package_version(gen) -> None:
    sample = json.loads(gen.sample_json)
    assert sample["version"] == gen.package_version


def test_fresh_tree_passes_check(mod, gen, tmp_path: Path) -> None:
    mod.write_generation(gen, tmp_path)
    assert mod.check_generation(gen, tmp_path) == []


def test_check_mode_detects_manual_edit(mod, gen, tmp_path: Path) -> None:
    mod.write_generation(gen, tmp_path)
    checks = tmp_path / "docs" / "reference" / "checks.md"
    checks.write_text(checks.read_text(encoding="utf-8") + "\n<!-- manual edit -->\n", "utf-8")

    assert "generated_file_drift:checks.md" in mod.check_generation(gen, tmp_path)


def test_check_mode_detects_stale_version(mod, gen, tmp_path: Path) -> None:
    mod.write_generation(gen, tmp_path)
    sample = tmp_path / "examples" / "sample-report" / "security-license-lens-report.json"
    data = json.loads(sample.read_text(encoding="utf-8"))
    data["version"] = "9.9.9"
    sample.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    problems = mod.check_generation(gen, tmp_path)

    assert any(problem.startswith("sample_version_mismatch") for problem in problems)


def test_check_mode_detects_secret_in_sample(mod, gen, tmp_path: Path) -> None:
    mod.write_generation(gen, tmp_path)
    sample = tmp_path / "examples" / "sample-report" / "security-license-lens-report.json"
    data = json.loads(sample.read_text(encoding="utf-8"))
    data["warnings"] = ["client_secret=super-secret-value"]
    sample.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    assert "sample_secret:secret:client_secret" in mod.check_generation(gen, tmp_path)


def test_generator_rejects_orphan_check(mod, monkeypatch: pytest.MonkeyPatch) -> None:
    import licenselens.catalog.reference as reference
    from licenselens.engine.registry import AssessmentRegistry, default_registry

    registry = default_registry()
    evaluators = {
        key: value for key, value in registry.evaluators.items() if key != "id-ca-priv-gaps"
    }
    slim = AssessmentRegistry(
        data_sources=registry.data_sources,
        collectors=registry.collectors,
        evaluators=evaluators,
    )
    monkeypatch.setattr(reference, "default_registry", lambda: slim)

    with pytest.raises(ReferenceCatalogError) as exc_info:
        mod.build_generation()

    assert "orphan_check:id-ca-priv-gaps" in exc_info.value.diagnostics


def test_sanitize_sample_result_redacts_identifiers(mod) -> None:
    result = ScanResult(
        version="0.3.0",
        scanned_at="2026-08-13T00:00:00+00:00",
        tenant_id="11111111-1111-1111-1111-111111111111",
        tenant_display_name="Real Customer Ltd",
        tenant_slug="real-customer",
        workspace_resource_id="/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )

    mod.sanitize_sample_result(result)

    assert result.tenant_id == ZERO_TENANT_ID
    assert result.tenant_display_name == "Demo (synthetic data)"
    assert result.tenant_slug is None
    assert result.workspace_resource_id is None


def test_find_secrets_detects_credentials(mod) -> None:
    assert mod.find_secrets('{"client_secret": "leak"}') == ["secret:client_secret"]
    assert "secret:access_token" in mod.find_secrets("Authorization: Bearer access_token=abc")
    assert mod.find_secrets(f'{{"tenant_id": "{ZERO_TENANT_ID}"}}') == []


def test_main_fails_on_drift_without_claiming_success(mod, gen, tmp_path: Path, capsys) -> None:
    mod.write_generation(gen, tmp_path)
    checks = tmp_path / "docs" / "reference" / "capabilities.md"
    checks.write_text("tampered", encoding="utf-8")

    code = mod.main(["--check", "--root", str(tmp_path)])
    out = capsys.readouterr().out

    assert code == 1
    assert "FAIL" in out
    assert "PASS" not in out


def test_main_succeeds_on_fresh_tree(mod, gen, tmp_path: Path, capsys) -> None:
    mod.write_generation(gen, tmp_path)

    code = mod.main(["--check", "--root", str(tmp_path)])
    out = capsys.readouterr().out

    assert code == 0
    assert "PASS" in out
    assert "FAIL" not in out

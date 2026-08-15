"""Fail-closed contract tests for the Todo 36 master release gate.

Locks the negative ("ultraqa") invariants of ``scripts/release_gate.py`` so the
gate cannot be fooled by malformed input, stale generated state, a dirty
worktree, or a misleading success output (a step that exits 0 without producing
its required artifact). These tests run everywhere and do not touch the real
repo tree — any filesystem mutation uses ``tmp_path``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts" / "release_gate.py"


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location("release_gate", GATE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["release_gate"] = module
    spec.loader.exec_module(module)
    return module


def _true_step(gate, **overrides):
    kwargs = {
        "id": "t",
        "title": "t",
        "argv": (sys.executable, "-c", "print('ok')"),
        "allow_codes": (0,),
    }
    kwargs.update(overrides)
    return gate.Step(**kwargs)


# ---------------------------------------------------------------------------
# Misleading success output — exit 0 without a required artifact must FAIL
# ---------------------------------------------------------------------------


def test_step_with_missing_required_output_fails(gate, tmp_path) -> None:
    missing = tmp_path / "does-not-exist.txt"
    result = gate.run_step(_true_step(gate, required_outputs=(str(missing),)))
    assert result.status == "fail"
    assert "missing required output" in result.note


def test_step_with_missing_required_marker_fails(gate) -> None:
    result = gate.run_step(_true_step(gate, required_markers=("MUST_NEVER_APPEAR",)))
    assert result.status == "fail"
    assert "missing required marker" in result.note


def test_step_with_unexpected_exit_code_fails(gate) -> None:
    step = _true_step(
        gate,
        argv=(sys.executable, "-c", "raise SystemExit(3)"),
        allow_codes=(0,),
    )
    result = gate.run_step(step)
    assert result.status == "fail"
    assert "exit 3" in result.note


# ---------------------------------------------------------------------------
# Malformed input — spawn/usage failures are typed, never a traceback
# ---------------------------------------------------------------------------


def test_nonexistent_binary_fails_closed(gate) -> None:
    result = gate.run_step(
        gate.Step("bad", "bad", ("/definitely/not/a/real/binary-xyz",), allow_codes=(0,))
    )
    assert result.status == "fail"
    assert "spawn failed" in result.note


# ---------------------------------------------------------------------------
# Secret / absolute-path / source-leakage scanning is deterministic
# ---------------------------------------------------------------------------


def test_scan_text_flags_secret_and_absolute_path(gate) -> None:
    problems = gate.scan_text(
        'AZURE_CLIENT_SECRET="super-secret-value-123"\npath /Users/janedoe/project\n',
        "sample.txt",
    )
    assert any(p.startswith("secret_value:") for p in problems)
    assert any(p.startswith("absolute_path:") for p in problems)


def test_scan_text_ignores_arm_resource_ids(gate) -> None:
    # Azure ARM ids and workspace paths are not host filesystem paths.
    arm_id = (
        '{"workspace_resource_id": '
        '"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/demo-rg"} '
        '"/providers/Microsoft.OperationalInsights/workspaces/demo"'
    )
    problems = gate.scan_text(arm_id, "sample.json")
    assert problems == []


def test_scan_text_ignores_bare_secret_names(gate) -> None:
    # Bare credential names are legitimate vocabulary (auth modes, env names).
    problems = gate.scan_text("- client_secret\n- access_token\n- api_key\n", "lab.yaml")
    assert problems == []


def test_scan_wheel_flags_source_leakage(gate, tmp_path) -> None:
    import zipfile

    wheel = tmp_path / "leak.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("licenselens/__init__.py", "x = 1")
        zf.writestr("tests/leak.json", '{"token": "AZURE_CLIENT_SECRET=realvalue123"}')
    problems = gate.scan_wheel(wheel)
    assert any("source_leakage" in p for p in problems)
    assert any(p.startswith("secret_value:") for p in problems)


# ---------------------------------------------------------------------------
# Dirty worktree — stray backslash directories are flagged
# ---------------------------------------------------------------------------


def test_stray_artifacts_flags_backslash_dirs(
    gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = r"\private\tmp\Pester_abc\LicenseLens"
    if sys.platform == "win32":
        (tmp_path / "seed").mkdir()
        original_rglob = Path.rglob

        class _SyntheticPath:
            name = marker
            parts = (*tmp_path.parts, marker)

            def is_symlink(self) -> bool:
                return False

            def __str__(self) -> str:
                return f"{tmp_path}{marker}"

        def _rglob(self: Path, pattern: str):
            yield from original_rglob(self, pattern)
            if self.resolve() == tmp_path.resolve():
                yield _SyntheticPath()

        monkeypatch.setattr(Path, "rglob", _rglob)
    else:
        stray = tmp_path / marker
        stray.mkdir(parents=True, exist_ok=True)
        assert "\\" in stray.name

    problems = gate.stray_artifact_problems(tmp_path)
    assert any(p.startswith("stray_backslash_path") for p in problems)


def test_stray_artifacts_clean_tree_has_no_problems(gate, tmp_path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "licenselens").mkdir()
    (tmp_path / "src" / "licenselens" / "cli.py").write_text("x = 1")
    assert gate.stray_artifact_problems(tmp_path) == []


# ---------------------------------------------------------------------------
# Stale state — a tampered generated file is flagged by the generator check
# ---------------------------------------------------------------------------


def test_reference_docs_check_flags_stale_file(gate, tmp_path) -> None:
    # check_reference_docs_freshness is repo-scoped; assert the underlying
    # generator's drift detection (which the gate wraps) rejects a stale file.
    spec = importlib.util.spec_from_file_location(
        "generate_reference_docs",
        ROOT / "scripts" / "generate_reference_docs.py",
    )
    gen = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["generate_reference_docs"] = gen
    spec.loader.exec_module(gen)

    generation = gen.build_generation()
    # A hand edit to a generated file must surface as drift.
    target = tmp_path / "docs" / "reference" / "checks.md"
    target.parent.mkdir(parents=True)
    target.write_text("// tampered\n", encoding="utf-8")
    problems = gen.check_generation(generation, root=tmp_path)
    assert any(p.startswith("generated_file_drift") for p in problems)

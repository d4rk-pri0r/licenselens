"""RED contract: release gate must fail closed on deferred steps (AF-G1/G2)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts" / "release_gate.py"


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location("release_gate_red", GATE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["release_gate_red"] = module
    spec.loader.exec_module(module)
    return module


def test_release_gate_exits_nonzero_when_any_step_is_deferred(
    gate,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deferred Windows exe / live-tenant steps must fail the gate (not exit 0)."""
    monkeypatch.setattr(gate, "build_steps", lambda *_a, **_k: ())

    def _pass_check() -> object:
        return gate.StepResult(
            id="noop",
            title="noop",
            status="pass",
            exit_code=0,
            duration_ms=0,
            summary="ok",
        )

    for name in (
        "check_release_guards",
        "check_release_scripts",
        "check_reference_docs_determinism",
        "check_reference_docs_freshness",
        "check_report_assets_determinism",
        "check_wheel_smoke",
        "check_checksums",
        "check_secret_and_path_scan",
        "check_source_leakage",
        "check_stray_artifacts",
    ):
        if hasattr(gate, name):
            monkeypatch.setattr(gate, name, _pass_check)

    out = tmp_path / "gate-out"
    code = gate.main(["--out", str(out), "--skip-browser"])

    payload = json.loads((out / "release-gate.json").read_text(encoding="utf-8"))
    deferred_count = int(payload.get("deferred") or 0)
    assert deferred_count >= 2, (
        f"expected windows-exe-build and live-tenant deferred entries, got {payload!r}"
    )
    assert code != 0, (
        "release_gate.py must exit nonzero when any step is deferred "
        f"(windows-exe-build / live-tenant); got exit {code} with "
        f"deferred={deferred_count} (AF-G1/G2)"
    )


def test_release_gate_treats_deferred_like_failure_in_exit_aggregation(gate) -> None:
    """Exit aggregation policy must count deferred toward failure."""
    results = [
        gate.StepResult("ok", "ok", "pass", 0, 0, "ok"),
        gate.deferred_result(
            "windows-exe-build",
            "Windows x64 PyInstaller",
            "deferred on this host",
        ),
        gate.deferred_result(
            "live-tenant",
            "Controlled live-tenant validation",
            "deferred pending credentials",
        ),
    ]
    failed = [r for r in results if r.status == "fail"]
    deferred = [r for r in results if r.status == "deferred"]

    intended_exit = 1 if (failed or deferred) else 0
    assert intended_exit == 1

    # Live main() policy replicated from scripts/release_gate.py:
    #   return 1 if failed else 0
    live_exit = 1 if failed else 0
    assert live_exit != 0, (
        "release_gate main still returns 0 when steps are only deferred "
        f"(failed={len(failed)} deferred={len(deferred)}) (AF-G1/G2)"
    )

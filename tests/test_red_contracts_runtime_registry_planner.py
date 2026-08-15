"""RED contracts: runtime must use typed registry + EvidencePlanner (AF-A / MH-02)."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from licenselens.auth import AuthMode, build_auth_context
from licenselens.engine.runner import run_scan
from licenselens.models import Workload


def test_run_scan_invokes_evidence_planner_collect(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI/batch ``run_scan`` path must call ``EvidencePlanner.collect``."""
    import licenselens.batch as batch_mod
    import licenselens.cli as cli_mod
    from licenselens.engine.planner import EvidencePlanner

    assert "run_scan" in inspect.getsource(cli_mod)
    assert "run_scan" in inspect.getsource(batch_mod)

    planner_calls: list[str] = []
    original = EvidencePlanner.collect

    def _tracking_collect(self: Any, *args: Any, **kwargs: Any) -> Any:
        planner_calls.append("collect")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(EvidencePlanner, "collect", _tracking_collect)

    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    run_scan(auth, dry_run=True)

    assert planner_calls, (
        "run_scan must invoke EvidencePlanner.collect; "
        "legacy _gather_evidence path is forbidden (AF-A)"
    )


def test_run_scan_dispatches_evaluators_through_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check evaluation must resolve callables via the typed registry, not EVALUATORS."""
    import licenselens.engine.runner as runner_mod
    from licenselens.engine.registry import AssessmentRegistry, default_registry

    registry = default_registry()
    resolved: list[str] = []
    original_for = AssessmentRegistry.evaluator_for

    def _tracking_evaluator_for(self: AssessmentRegistry, check_id: str) -> Any:
        resolved.append(check_id)
        return original_for(self, check_id)

    monkeypatch.setattr(AssessmentRegistry, "evaluator_for", _tracking_evaluator_for)
    monkeypatch.setattr(runner_mod, "default_registry", lambda: registry, raising=False)

    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    run_scan(auth, dry_run=True, workloads=[Workload.IDENTITY])

    assert resolved, (
        "run_scan must dispatch checks through AssessmentRegistry.evaluator_for; "
        "central EVALUATORS switchboard dispatch is forbidden (AF-A)"
    )


def test_run_scan_source_forbids_legacy_gather_and_evaluators_map() -> None:
    """Structural guard: runner orchestration must not reference legacy switchboards."""
    import licenselens.engine.runner as runner_mod

    run_src = inspect.getsource(runner_mod.run_scan)
    eval_src = inspect.getsource(runner_mod._evaluate_check)

    assert "_gather_evidence" not in run_src, (
        "run_scan still calls _gather_evidence; must collect via EvidencePlanner"
    )
    assert "EVALUATORS" not in eval_src, (
        "runner still dispatches through EVALUATORS; must use registry callables"
    )


def test_narrow_workload_scan_skips_unrelated_collectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identity-only scan must not materialize MDE/ARM/collaboration evidence."""
    from licenselens.engine.planner import EvidencePlanner

    captured: list[set[str]] = []
    original = EvidencePlanner.collect

    def _tracking_collect(self: Any, *args: Any, **kwargs: Any) -> Any:
        result = original(self, *args, **kwargs)
        captured.append({str(key) for key in result.envelopes})
        return result

    monkeypatch.setattr(EvidencePlanner, "collect", _tracking_collect)

    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    run_scan(auth, dry_run=True, workloads=[Workload.IDENTITY])

    assert captured, "expected evidence collection during scan"
    keys = captured[0]
    unrelated = {
        "mde_summary",
        "mde_health",
        "defender_for_cloud_pricings",
        "collaboration_bundle",
        "sentinel_rules",
        "sentinel_ueba",
        "intune_bundle",
        "security_alerts_bundle",
    }
    leaked = sorted(keys & unrelated)
    assert not leaked, (
        "narrow identity workload must not gather unrelated Graph/MDE/ARM/"
        f"collaboration evidence keys; leaked={leaked}"
    )

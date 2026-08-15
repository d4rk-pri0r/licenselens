from __future__ import annotations

from dataclasses import replace

import pytest

from licenselens.engine.loader import load_checks
from licenselens.engine.registry import AssessmentRegistry, default_registry
from licenselens.engine.runner import _evaluate_check
from licenselens.models import FindingStatus


def test_workload_evaluator_registry_matches_current_enabled_checks() -> None:
    # Given: the shipped enabled check catalog.
    from licenselens.evaluators import evaluator_for_check, evidence_keys_for_check

    checks = tuple(check for check in load_checks() if check.enabled)
    registry = default_registry()

    # When: each check resolves through the typed registry callables.
    resolved = {check.id: evaluator_for_check(check.id).__name__ for check in checks}

    # Then: all current checks have evaluator callables and evidence contracts.
    assert set(resolved) == {check.id for check in checks}
    assert set(registry.evaluators) == set(resolved)
    assert all(evidence_keys_for_check(check.id) for check in checks)
    assert all(registry.evaluator_for(check.id).evaluate is not None for check in checks)


def test_missing_evaluator_becomes_skipped_boundary_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: an otherwise eligible check whose evaluator was not registered.
    check = next(check for check in load_checks() if check.id == "id-ca-priv-gaps")
    owned = set(check.required_capabilities)
    registry = default_registry()
    evaluators = {
        key: value for key, value in registry.evaluators.items() if key != check.id
    }
    slim = AssessmentRegistry(
        data_sources=registry.data_sources,
        collectors=registry.collectors,
        evaluators=evaluators,
    )
    monkeypatch.setattr("licenselens.engine.runner.default_registry", lambda: slim)

    # When: runner evaluates the check at its boundary.
    finding = _evaluate_check(check, owned, {})

    # Then: the missing implementation is an explicit skipped finding, not success.
    assert finding.status is FindingStatus.SKIPPED
    assert finding.evidence["collector"] == check.collector


def test_thrown_evaluator_becomes_error_boundary_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: an otherwise eligible check whose evaluator raises unexpectedly.
    from licenselens.engine.evaluate import Evaluation

    check = next(check for check in load_checks() if check.id == "id-ca-priv-gaps")
    owned = set(check.required_capabilities)
    registry = default_registry()
    entry = registry.evaluator_for(check.id)

    def fail_evaluator(_check, _evidence) -> Evaluation:
        raise RuntimeError("simulated evaluator failure")

    broken_entry = replace(entry, evaluate=fail_evaluator)
    evaluators = dict(registry.evaluators)
    evaluators[check.id] = broken_entry
    slim = AssessmentRegistry(
        data_sources=registry.data_sources,
        collectors=registry.collectors,
        evaluators=evaluators,
    )
    monkeypatch.setattr("licenselens.engine.runner.default_registry", lambda: slim)

    # When: runner evaluates the check at its boundary.
    finding = _evaluate_check(
        check,
        owned,
        {"ca_policies": [], "role_assignments": []},
    )

    # Then: the exception is converted to a typed error finding.
    assert finding.status is FindingStatus.ERROR
    assert finding.evidence == {"error": "simulated evaluator failure"}

from __future__ import annotations

import pytest

from licenselens.engine.loader import load_checks
from licenselens.engine.registry import (
    Backend,
    CollectorEntry,
    DataSourceEntry,
    DependencyCycleError,
    DuplicateRegistryIdError,
    EvaluatorEntry,
    MissingRegistryOutputError,
    build_registry,
    default_registry,
    dump_registry_json,
)
from licenselens.schema_contracts import EvaluationMode


def test_default_registry_resolves_all_current_checks_deterministically() -> None:
    # Given: the shipped check catalog and typed executable registry.
    registry = default_registry()
    enabled_checks = [check for check in load_checks() if check.enabled]

    # When: each check resolves through the typed registry surface.
    resolved = [registry.evaluator_for(check.id).id for check in enabled_checks]
    callables = {check.id: registry.evaluator_callable(check.id) for check in enabled_checks}
    first = dump_registry_json(registry)
    second = dump_registry_json(default_registry())

    # Then: resolution covers every enabled check with bound callables and stable dump.
    assert sorted(resolved) == sorted(registry.evaluators)
    assert first == second
    assert len(callables) == len(enabled_checks)
    assert all(callable(fn) for fn in callables.values())
    assert all("." in entry.evaluator for entry in registry.evaluator_entries)
    assert all(entry.evaluate is not None for entry in registry.evaluator_entries)
    assert all(entry.input_models for entry in registry.evaluator_entries)


def test_default_registry_binds_proxy_evaluators_to_proxy_mode() -> None:
    # Given: the default registry contains direct and proxy evaluators.
    registry = default_registry()

    # When: evaluator metadata is inspected.
    proxy_modes = {
        entry.id: entry.evaluation_mode
        for entry in registry.evaluator_entries
        if entry.evaluation_mode is EvaluationMode.PROXY
    }

    # Then: only static Secure Score proxy checks are labeled proxy.
    assert proxy_modes == {
        "mdi-sensors-missing": EvaluationMode.PROXY,
    }
    assert (
        registry.evaluator_for("mdo-p2-policies-default").evaluation_mode
        is EvaluationMode.DIRECT_WITH_PROXY_FALLBACK
    )
    assert (
        registry.evaluator_for("pur-dlp-not-enforced").evaluation_mode
        is EvaluationMode.DIRECT_WITH_PROXY_FALLBACK
    )


def test_default_registry_binds_collector_factories() -> None:
    registry = default_registry()
    assert registry.collectors
    assert all(entry.factory is not None for entry in registry.collector_entries)
    sample = next(iter(registry.collector_entries))
    specs = sample.factory()
    assert specs
    assert all(spec.produces for spec in specs)


def test_registry_rejects_duplicate_ids() -> None:
    # Given: two data-source entries claim the same ID.
    source = _source("ca_policies")

    # When / Then: startup validation fails with a typed duplicate diagnostic.
    with pytest.raises(DuplicateRegistryIdError) as exc_info:
        build_registry(
            data_sources=(source, source),
            collectors=(),
            evaluators=(),
        )
    assert str(exc_info.value) == "duplicate data_source registry id: ca_policies"


def test_registry_rejects_missing_outputs() -> None:
    # Given: an evaluator depends on evidence no collector or data source produces.
    evaluator = EvaluatorEntry(
        id="check-a",
        evaluator="evaluate_a",
        input_models=("missing_evidence",),
        output_model="Evaluation",
        backend=Backend.NOOP,
        permissions=(),
        cloud_support=("public",),
        cache_key="check-a",
        timeout_seconds=1,
        dependencies=("missing_evidence",),
        evaluation_mode=EvaluationMode.DIRECT,
    )

    # When / Then: startup validation names the missing output binding.
    with pytest.raises(MissingRegistryOutputError) as exc_info:
        build_registry(data_sources=(), collectors=(), evaluators=(evaluator,))
    assert str(exc_info.value) == "check-a depends on missing registry output: missing_evidence"


def test_registry_rejects_dependency_cycles() -> None:
    # Given: collectors form a dependency cycle.
    first = _collector("first", dependencies=("second",))
    second = _collector("second", dependencies=("first",))

    # When / Then: startup validation reports the cycle before runtime planning.
    with pytest.raises(DependencyCycleError) as exc_info:
        build_registry(data_sources=(), collectors=(first, second), evaluators=())
    assert str(exc_info.value) == "registry dependency cycle: first -> second -> first"


def _source(entry_id: str) -> DataSourceEntry:
    return DataSourceEntry(
        id=entry_id,
        output_model="list[JsonObject]",
        backend=Backend.GRAPH,
        permissions=("Policy.Read.All",),
        cloud_support=("public",),
        cache_key=entry_id,
        timeout_seconds=30,
        dependencies=(),
    )


def _collector(entry_id: str, *, dependencies: tuple[str, ...]) -> CollectorEntry:
    return CollectorEntry(
        id=entry_id,
        collector="collect_" + entry_id,
        output_model="list[JsonObject]",
        backend=Backend.GRAPH,
        permissions=("Directory.Read.All",),
        cloud_support=("public",),
        cache_key=entry_id,
        timeout_seconds=30,
        dependencies=dependencies,
    )

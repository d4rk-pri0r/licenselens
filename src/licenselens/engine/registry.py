from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum, unique
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

from licenselens.schema_contracts import EvaluationMode

if TYPE_CHECKING:
    from licenselens.engine.planner import CollectorSpec
    from licenselens.evaluators.common import Evaluator

type JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
type JsonObject = dict[str, JsonValue]
type CollectorSpecFactory = Callable[..., Sequence["CollectorSpec"]]


@unique
class Backend(StrEnum):
    GRAPH = "graph"
    MDE = "mde"
    ARM = "arm"
    PROXY = "proxy"
    NOOP = "noop"


@dataclass(frozen=True, slots=True)
class DuplicateRegistryIdError(Exception):
    kind: str
    entry_id: str

    def __str__(self) -> str:
        return f"duplicate {self.kind} registry id: {self.entry_id}"


@dataclass(frozen=True, slots=True)
class MissingRegistryOutputError(Exception):
    entry_id: str
    dependency_id: str

    def __str__(self) -> str:
        return f"{self.entry_id} depends on missing registry output: {self.dependency_id}"


@dataclass(frozen=True, slots=True)
class DependencyCycleError(Exception):
    cycle: tuple[str, ...]

    def __str__(self) -> str:
        return "registry dependency cycle: " + " -> ".join(self.cycle)


@dataclass(frozen=True, slots=True)
class DataSourceEntry:
    id: str
    output_model: str
    backend: Backend
    permissions: tuple[str, ...]
    cloud_support: tuple[str, ...]
    cache_key: str
    timeout_seconds: int
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CollectorEntry:
    id: str
    collector: str
    output_model: str
    backend: Backend
    permissions: tuple[str, ...]
    cloud_support: tuple[str, ...]
    cache_key: str
    timeout_seconds: int
    dependencies: tuple[str, ...]
    factory: CollectorSpecFactory | None = None


@dataclass(frozen=True, slots=True)
class EvaluatorEntry:
    id: str
    evaluator: str
    input_models: tuple[str, ...]
    output_model: str
    backend: Backend
    permissions: tuple[str, ...]
    cloud_support: tuple[str, ...]
    cache_key: str
    timeout_seconds: int
    dependencies: tuple[str, ...]
    evaluation_mode: EvaluationMode
    evaluate: Evaluator | None = None


class RegistryNode(Protocol):
    id: str
    dependencies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AssessmentRegistry:
    data_sources: Mapping[str, DataSourceEntry]
    collectors: Mapping[str, CollectorEntry]
    evaluators: Mapping[str, EvaluatorEntry]

    @property
    def data_source_entries(self) -> tuple[DataSourceEntry, ...]:
        return tuple(self.data_sources[key] for key in sorted(self.data_sources))

    @property
    def collector_entries(self) -> tuple[CollectorEntry, ...]:
        return tuple(self.collectors[key] for key in sorted(self.collectors))

    @property
    def evaluator_entries(self) -> tuple[EvaluatorEntry, ...]:
        return tuple(self.evaluators[key] for key in sorted(self.evaluators))

    def evaluator_for(self, check_id: str) -> EvaluatorEntry:
        return self.evaluators[check_id]

    def evaluator_callable(self, check_id: str) -> Evaluator:
        entry = self.evaluator_for(check_id)
        if entry.evaluate is None:
            raise KeyError(check_id)
        return entry.evaluate


def build_registry(
    *,
    data_sources: Sequence[DataSourceEntry],
    collectors: Sequence[CollectorEntry],
    evaluators: Sequence[EvaluatorEntry],
) -> AssessmentRegistry:
    data_source_map = _index("data_source", data_sources)
    collector_map = _index("collector", collectors)
    evaluator_map = _index("evaluator", evaluators)
    nodes: dict[str, RegistryNode] = {}
    for entry in (*data_sources, *collectors, *evaluators):
        if entry.id in nodes:
            raise DuplicateRegistryIdError(kind="global", entry_id=entry.id)
        nodes[entry.id] = entry
    data_source_ids = set(data_source_map)
    for evaluator in evaluators:
        for input_model in evaluator.input_models:
            if input_model not in data_source_ids:
                raise MissingRegistryOutputError(evaluator.id, input_model)
    _reject_missing_dependencies(nodes)
    _reject_cycles(nodes)
    return AssessmentRegistry(
        data_sources=MappingProxyType(data_source_map),
        collectors=MappingProxyType(collector_map),
        evaluators=MappingProxyType(evaluator_map),
    )


def default_registry() -> AssessmentRegistry:
    from licenselens.engine._registry_defaults import build_default_registry

    return build_default_registry()


def evidence_keys_by_check(registry: AssessmentRegistry) -> dict[str, list[str]]:
    return {entry.id: list(entry.input_models) for entry in registry.evaluator_entries}


def dump_registry_json(registry: AssessmentRegistry) -> str:
    return json.dumps(_registry_json(registry), ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def _index[T: RegistryNode](kind: str, entries: Sequence[T]) -> dict[str, T]:
    indexed: dict[str, T] = {}
    for entry in entries:
        if entry.id in indexed:
            raise DuplicateRegistryIdError(kind=kind, entry_id=entry.id)
        indexed[entry.id] = entry
    return indexed


def _reject_missing_dependencies(nodes: Mapping[str, RegistryNode]) -> None:
    for node in nodes.values():
        for dependency in node.dependencies:
            if dependency not in nodes:
                raise MissingRegistryOutputError(node.id, dependency)


def _reject_cycles(nodes: Mapping[str, RegistryNode]) -> None:
    visited: set[str] = set()
    active: list[str] = []
    for node_id in sorted(nodes):
        _visit(node_id, nodes, visited, active)


def _visit(
    node_id: str,
    nodes: Mapping[str, RegistryNode],
    visited: set[str],
    active: list[str],
) -> None:
    if node_id in visited:
        return
    if node_id in active:
        start = active.index(node_id)
        raise DependencyCycleError(tuple([*active[start:], node_id]))
    active.append(node_id)
    for dependency in sorted(nodes[node_id].dependencies):
        _visit(dependency, nodes, visited, active)
    active.pop()
    visited.add(node_id)


def _registry_json(registry: AssessmentRegistry) -> JsonObject:
    return {
        "data_sources": [_entry_json(entry) for entry in registry.data_source_entries],
        "collectors": [_entry_json(entry) for entry in registry.collector_entries],
        "evaluators": [_entry_json(entry) for entry in registry.evaluator_entries],
    }


def _entry_json(entry: DataSourceEntry | CollectorEntry | EvaluatorEntry) -> JsonObject:
    base: JsonObject = {
        "id": entry.id,
        "output_model": entry.output_model,
        "backend": entry.backend.value,
        "permissions": list(entry.permissions),
        "cloud_support": list(entry.cloud_support),
        "cache_key": entry.cache_key,
        "timeout_seconds": entry.timeout_seconds,
        "dependencies": list(entry.dependencies),
    }
    match entry:
        case DataSourceEntry():
            return base
        case CollectorEntry(collector=collector):
            return {**base, "collector": collector}
        case EvaluatorEntry(evaluator=evaluator, input_models=input_models, evaluation_mode=mode):
            return {
                **base,
                "evaluator": evaluator,
                "input_models": list(input_models),
                "evaluation_mode": mode.value,
            }

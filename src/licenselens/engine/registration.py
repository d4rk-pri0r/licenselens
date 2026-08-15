"""Explicit registration helpers for typed assessment registry entries."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from licenselens.engine.planner import CollectorSpec
from licenselens.engine.registry import (
    Backend,
    CollectorEntry,
    DataSourceEntry,
    DuplicateRegistryIdError,
    EvaluatorEntry,
    build_registry,
)
from licenselens.evaluators.common import Evaluator
from licenselens.schema_contracts import EvaluationMode

type CollectorSpecFactory = Callable[..., Sequence[CollectorSpec]]
type JsonObject = dict[str, Any]


@dataclass(frozen=True, slots=True)
class MissingRegistrationMetadataError(Exception):
    entry_id: str
    field_name: str

    def __str__(self) -> str:
        return f"missing registration metadata for {self.entry_id}: {self.field_name}"


@dataclass(frozen=True, slots=True)
class ImportCycleRegistrationError(Exception):
    modules: tuple[str, ...]

    def __str__(self) -> str:
        return "registration import cycle: " + " -> ".join(self.modules)


def qualified_callable_name(fn: Callable[..., Any]) -> str:
    module = getattr(fn, "__module__", "") or ""
    qualname = getattr(fn, "__qualname__", "") or getattr(fn, "__name__", "")
    if module and qualname:
        return f"{module}.{qualname}"
    return qualname or module or "unknown"


@dataclass(slots=True)
class RegistrationCatalog:
    """Mutable builder that rejects duplicates and incomplete metadata at register time."""

    data_sources: dict[str, DataSourceEntry] = field(default_factory=dict)
    collectors: dict[str, CollectorEntry] = field(default_factory=dict)
    evaluators: dict[str, EvaluatorEntry] = field(default_factory=dict)
    _import_stack: list[str] = field(default_factory=list)

    def enter_module(self, module_name: str) -> None:
        if module_name in self._import_stack:
            start = self._import_stack.index(module_name)
            cycle = tuple([*self._import_stack[start:], module_name])
            raise ImportCycleRegistrationError(cycle)
        self._import_stack.append(module_name)

    def exit_module(self, module_name: str) -> None:
        if self._import_stack and self._import_stack[-1] == module_name:
            self._import_stack.pop()

    def add_data_source(self, entry: DataSourceEntry) -> DataSourceEntry:
        if not entry.id:
            raise MissingRegistrationMetadataError("<unknown>", "id")
        if not entry.output_model:
            raise MissingRegistrationMetadataError(entry.id, "output_model")
        if not entry.cache_key:
            raise MissingRegistrationMetadataError(entry.id, "cache_key")
        if entry.id in self.data_sources:
            raise DuplicateRegistryIdError(kind="data_source", entry_id=entry.id)
        self.data_sources[entry.id] = entry
        return entry

    def add_collector(
        self,
        *,
        collector_id: str,
        factory: CollectorSpecFactory,
        output_model: str,
        backend: Backend,
        permissions: Sequence[str],
        cloud_support: Sequence[str],
        cache_key: str,
        timeout_seconds: int,
        dependencies: Sequence[str],
    ) -> CollectorEntry:
        if not collector_id:
            raise MissingRegistrationMetadataError("<unknown>", "id")
        if factory is None:
            raise MissingRegistrationMetadataError(collector_id, "factory")
        if not output_model:
            raise MissingRegistrationMetadataError(collector_id, "output_model")
        if not cache_key:
            raise MissingRegistrationMetadataError(collector_id, "cache_key")
        if collector_id in self.collectors:
            raise DuplicateRegistryIdError(kind="collector", entry_id=collector_id)
        entry = CollectorEntry(
            id=collector_id,
            collector=qualified_callable_name(factory),
            factory=factory,
            output_model=output_model,
            backend=backend,
            permissions=tuple(permissions),
            cloud_support=tuple(cloud_support),
            cache_key=cache_key,
            timeout_seconds=timeout_seconds,
            dependencies=tuple(dependencies),
        )
        self.collectors[collector_id] = entry
        return entry

    def add_evaluator(
        self,
        *,
        check_id: str,
        evaluate: Evaluator,
        input_models: Sequence[str],
        collector_id: str,
        evaluation_mode: EvaluationMode = EvaluationMode.DIRECT,
        output_model: str = "Evaluation",
        backend: Backend | None = None,
        permissions: Sequence[str] = (),
        cloud_support: Sequence[str] = ("public",),
        cache_key: str | None = None,
        timeout_seconds: int = 5,
    ) -> EvaluatorEntry:
        if not check_id:
            raise MissingRegistrationMetadataError("<unknown>", "id")
        if evaluate is None:
            raise MissingRegistrationMetadataError(check_id, "evaluate")
        if not input_models:
            raise MissingRegistrationMetadataError(check_id, "input_models")
        if not collector_id:
            raise MissingRegistrationMetadataError(check_id, "collector_id")
        if check_id in self.evaluators:
            raise DuplicateRegistryIdError(kind="evaluator", entry_id=check_id)
        resolved_backend = backend
        if resolved_backend is None:
            resolved_backend = (
                Backend.PROXY
                if evaluation_mode
                in {EvaluationMode.PROXY, EvaluationMode.DIRECT_WITH_PROXY_FALLBACK}
                else Backend.NOOP
            )
        entry = EvaluatorEntry(
            id=check_id,
            evaluator=qualified_callable_name(evaluate),
            evaluate=evaluate,
            input_models=tuple(input_models),
            output_model=output_model,
            backend=resolved_backend,
            permissions=tuple(permissions),
            cloud_support=tuple(cloud_support),
            cache_key=cache_key or f"evaluation:{check_id}",
            timeout_seconds=timeout_seconds,
            dependencies=(collector_id,),
            evaluation_mode=evaluation_mode,
        )
        self.evaluators[check_id] = entry
        return entry

    def evaluator(
        self,
        check_id: str,
        *,
        input_models: Sequence[str],
        collector_id: str,
        evaluation_mode: EvaluationMode = EvaluationMode.DIRECT,
        permissions: Sequence[str] = (),
        backend: Backend | None = None,
    ) -> Callable[[Evaluator], Evaluator]:
        """Decorator form used beside evaluator implementations."""

        def decorator(fn: Evaluator) -> Evaluator:
            self.add_evaluator(
                check_id=check_id,
                evaluate=fn,
                input_models=input_models,
                collector_id=collector_id,
                evaluation_mode=evaluation_mode,
                permissions=permissions,
                backend=backend,
            )
            return fn

        return decorator

    def build(self) -> Any:
        return build_registry(
            data_sources=tuple(self.data_sources[key] for key in sorted(self.data_sources)),
            collectors=tuple(self.collectors[key] for key in sorted(self.collectors)),
            evaluators=tuple(self.evaluators[key] for key in sorted(self.evaluators)),
        )


def merge_permissions(
    source_ids: Sequence[str],
    source_meta: Mapping[str, tuple[Backend, tuple[str, ...], str, int]],
) -> tuple[str, ...]:
    permissions = {
        permission for source_id in source_ids for permission in source_meta[source_id][1]
    }
    return tuple(sorted(permissions))

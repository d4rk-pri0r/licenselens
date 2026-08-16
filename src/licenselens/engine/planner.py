from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from licenselens.collectors.contracts import (
    CheckId,
    CloudEnvironment,
    CollectionOutcome,
    CollectorId,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
)


@dataclass(frozen=True, slots=True)
class CollectionPlanError(Exception):
    diagnostic: str

    def __str__(self) -> str:
        return self.diagnostic


@dataclass(frozen=True, slots=True)
class CollectionContext:
    envelopes: Mapping[EvidenceKey, EvidenceEnvelope]


class EvidenceCollector(Protocol):
    def __call__(self, context: CollectionContext) -> CollectionOutcome: ...


#: Progress hook signature: (collector_id, step_index, step_count, envelope).
#: Invoked after every collection step so callers can render live per-source
#: status instead of hanging silently during long scans.
ProgressCallback = Callable[[CollectorId, int, int, EvidenceEnvelope], None]


@dataclass(frozen=True, slots=True)
class CollectorSpec:
    collector_id: CollectorId
    produces: EvidenceKey
    collect: EvidenceCollector
    depends_on: tuple[EvidenceKey, ...] = ()
    supported_clouds: tuple[CloudEnvironment, ...] = (CloudEnvironment.PUBLIC,)
    timeout_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class CheckEvidenceRequirement:
    check_id: CheckId
    evidence_keys: tuple[EvidenceKey, ...]
    enabled: bool = True
    profile_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlanStep:
    collector: CollectorSpec


@dataclass(frozen=True, slots=True)
class CollectionPlan:
    steps: tuple[PlanStep, ...]
    checks: tuple[CheckEvidenceRequirement, ...]
    max_concurrency: int


@dataclass(frozen=True, slots=True)
class PlanBuildState:
    ordered: list[PlanStep]
    permanent: set[EvidenceKey]
    temporary: set[EvidenceKey]


@dataclass(frozen=True, slots=True)
class CollectionResult:
    envelopes: Mapping[EvidenceKey, EvidenceEnvelope]
    checks: tuple[CheckEvidenceRequirement, ...]

    def envelope_for(self, key: EvidenceKey) -> EvidenceEnvelope:
        return self.envelopes.get(key, EvidenceEnvelope.missing(key))

    def check_health(self, check_id: CheckId) -> EvidenceHealth:
        requirements = tuple(check for check in self.checks if check.check_id == check_id)
        if not requirements:
            return EvidenceHealth.MISSING
        required = requirements[0].evidence_keys
        unhealthy = tuple(
            self.envelope_for(key).health
            for key in required
            if self.envelope_for(key).health is not EvidenceHealth.OK
        )
        if not unhealthy:
            return EvidenceHealth.OK
        return sorted(unhealthy, key=_health_rank)[0]


def _health_rank(health: EvidenceHealth) -> int:
    ranks = {
        EvidenceHealth.DENIED: 0,
        EvidenceHealth.ERROR: 1,
        EvidenceHealth.TRUNCATED: 2,
        EvidenceHealth.UNSUPPORTED: 3,
        EvidenceHealth.UNAVAILABLE: 4,
        EvidenceHealth.MISSING: 5,
        EvidenceHealth.OK: 6,
    }
    return ranks[health]


class EvidencePlanner:
    def __init__(
        self,
        *,
        collectors: Sequence[CollectorSpec],
        cloud: CloudEnvironment = CloudEnvironment.PUBLIC,
        max_concurrency: int = 4,
    ) -> None:
        self._collectors = tuple(collectors)
        self._cloud = cloud
        self._max_concurrency = max_concurrency
        self._producers = self._build_producers(self._collectors)

    def build_plan(
        self,
        checks: Sequence[CheckEvidenceRequirement],
        *,
        profile_ids: tuple[str, ...] = (),
    ) -> CollectionPlan:
        selected_checks = tuple(check for check in checks if _check_selected(check, profile_ids))
        state = PlanBuildState(ordered=[], permanent=set(), temporary=set())

        for key in sorted(_required_keys(selected_checks), key=str):
            self._visit(key, state)

        return CollectionPlan(
            steps=tuple(state.ordered),
            checks=selected_checks,
            max_concurrency=self._max_concurrency,
        )

    def collect(
        self,
        checks: Sequence[CheckEvidenceRequirement],
        *,
        profile_ids: tuple[str, ...] = (),
        progress: ProgressCallback | None = None,
    ) -> CollectionResult:
        plan = self.build_plan(checks, profile_ids=profile_ids)
        envelopes: dict[EvidenceKey, EvidenceEnvelope] = {}
        total = len(plan.steps)
        for index, step in enumerate(plan.steps):
            spec = step.collector
            envelope = self._collect_one(spec, envelopes)
            envelopes[spec.produces] = envelope
            if progress is not None:
                progress(spec.collector_id, index, total, envelope)
        return CollectionResult(envelopes=envelopes, checks=plan.checks)

    def _visit(self, key: EvidenceKey, state: PlanBuildState) -> None:
        if key in state.permanent:
            return
        if key in state.temporary:
            raise CollectionPlanError(f"collector dependency cycle at {key}")
        producer = self._producer_for(key)
        state.temporary.add(key)
        for dependency in sorted(producer.depends_on, key=str):
            self._visit(dependency, state)
        state.temporary.remove(key)
        state.permanent.add(key)
        state.ordered.append(PlanStep(collector=producer))

    def _producer_for(self, key: EvidenceKey) -> CollectorSpec:
        producer = self._producers.get(key)
        if producer is None:
            raise CollectionPlanError(f"no collector produces required evidence {key}")
        return producer

    def _collect_one(
        self,
        spec: CollectorSpec,
        envelopes: Mapping[EvidenceKey, EvidenceEnvelope],
    ) -> EvidenceEnvelope:
        if self._cloud not in spec.supported_clouds:
            return EvidenceEnvelope.unsupported(
                spec.produces,
                reason=f"collector {spec.collector_id} does not support {self._cloud.value}",
            )
        blocked = _blocked_dependency(spec, envelopes)
        if blocked is not None:
            return EvidenceEnvelope.unavailable(
                spec.produces,
                reason=f"dependency {blocked.key} is {blocked.health.value}",
            )
        try:
            outcome = spec.collect(CollectionContext(envelopes=dict(envelopes)))
        except Exception as exc:
            return EvidenceEnvelope.error(spec.produces, reason=str(exc))
        if outcome.key != spec.produces:
            return EvidenceEnvelope.error(
                spec.produces,
                reason=f"collector {spec.collector_id} returned {outcome.key}",
            )
        return outcome

    @staticmethod
    def _build_producers(
        collectors: Sequence[CollectorSpec],
    ) -> Mapping[EvidenceKey, CollectorSpec]:
        producers: dict[EvidenceKey, CollectorSpec] = {}
        for collector in collectors:
            if collector.produces in producers:
                raise CollectionPlanError(f"duplicate producer for evidence {collector.produces}")
            producers[collector.produces] = collector
        return producers


def _check_selected(
    check: CheckEvidenceRequirement,
    profile_ids: tuple[str, ...],
) -> bool:
    if not check.enabled:
        return False
    profile_matches = bool(set(check.profile_ids) & set(profile_ids))
    return not profile_ids or not check.profile_ids or profile_matches


def _required_keys(checks: Sequence[CheckEvidenceRequirement]) -> frozenset[EvidenceKey]:
    return frozenset(key for check in checks for key in check.evidence_keys)


def _blocked_dependency(
    spec: CollectorSpec,
    envelopes: Mapping[EvidenceKey, EvidenceEnvelope],
) -> EvidenceEnvelope | None:
    for dependency in spec.depends_on:
        envelope = envelopes.get(dependency, EvidenceEnvelope.missing(dependency))
        if not envelope.is_usable:
            return envelope
    return None

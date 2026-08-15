from __future__ import annotations

import pytest

from licenselens.collectors.contracts import (
    CheckId,
    CloudEnvironment,
    CollectionMetadata,
    CollectionOutcome,
    CollectorId,
    EvidenceEnvelope,
    EvidenceHealth,
    EvidenceKey,
    JsonValue,
    PaginationMetadata,
)
from licenselens.engine.planner import (
    CheckEvidenceRequirement,
    CollectionContext,
    CollectionPlanError,
    CollectorSpec,
    EvidencePlanner,
)


def _check(check_id: str, *keys: EvidenceKey) -> CheckEvidenceRequirement:
    return CheckEvidenceRequirement(
        check_id=CheckId(check_id),
        evidence_keys=keys,
    )


def _metadata(items_collected: int = 1) -> CollectionMetadata:
    return CollectionMetadata(
        source="fake",
        items_collected=items_collected,
        pagination=PaginationMetadata(pages_read=1, max_pages=1),
    )


def _ok(key: EvidenceKey, value: JsonValue = "ok") -> EvidenceEnvelope:
    return EvidenceEnvelope(
        key=key,
        health=EvidenceHealth.OK,
        value=value,
        metadata=_metadata(),
    )


def _collector(
    collector_id: str,
    key: EvidenceKey,
    calls: list[str],
    outcome: CollectionOutcome,
    *,
    depends_on: tuple[EvidenceKey, ...] = (),
    supported_clouds: tuple[CloudEnvironment, ...] = (CloudEnvironment.PUBLIC,),
) -> CollectorSpec:
    def collect(_context: CollectionContext) -> CollectionOutcome:
        calls.append(collector_id)
        return outcome

    return CollectorSpec(
        collector_id=CollectorId(collector_id),
        produces=key,
        collect=collect,
        depends_on=depends_on,
        supported_clouds=supported_clouds,
    )


def test_shared_evidence_collected_once_when_two_checks_require_it() -> None:
    shared = EvidenceKey("graph.ca_policies")
    calls: list[str] = []
    planner = EvidencePlanner(
        collectors=(_collector("graph.ca", shared, calls, _ok(shared)),),
    )

    # Given: two enabled checks that require the same evidence key.
    checks = (_check("id-ca-priv-gaps", shared), _check("id-idprotect-off", shared))

    # When: the planner resolves and executes the evidence DAG.
    result = planner.collect(checks)

    # Then: the shared collector runs once and both checks receive the ok envelope.
    assert calls == ["graph.ca"]
    assert result.envelope_for(shared).health is EvidenceHealth.OK
    assert result.check_health(CheckId("id-ca-priv-gaps")) is EvidenceHealth.OK
    assert result.check_health(CheckId("id-idprotect-off")) is EvidenceHealth.OK


def test_denied_dependency_blocks_downstream_without_blocking_independent_branch() -> None:
    source = EvidenceKey("graph.secure_score")
    derived = EvidenceKey("purview.dlp")
    independent = EvidenceKey("mde.machines")
    calls: list[str] = []
    denied = EvidenceEnvelope.denied(source, reason="403 Authorization_RequestDenied")
    planner = EvidencePlanner(
        collectors=(
            _collector("graph.secure_score", source, calls, denied),
            _collector("purview.dlp", derived, calls, _ok(derived), depends_on=(source,)),
            _collector("mde.machines", independent, calls, _ok(independent)),
        ),
    )

    # Given: one branch depends on a denied source while another branch is independent.
    checks = (_check("pur-dlp-not-enforced", derived), _check("mde-onboard-gap", independent))

    # When: the planner executes the DAG.
    result = planner.collect(checks)

    # Then: denied evidence propagates, the derived collector is not called, and MDE succeeds.
    assert set(calls) == {"graph.secure_score", "mde.machines"}
    assert "purview.dlp" not in calls
    assert result.envelope_for(derived).health is EvidenceHealth.UNAVAILABLE
    assert result.check_health(CheckId("pur-dlp-not-enforced")) is EvidenceHealth.UNAVAILABLE
    assert result.check_health(CheckId("mde-onboard-gap")) is EvidenceHealth.OK


def test_raised_collector_error_does_not_block_independent_branch() -> None:
    failing = EvidenceKey("collector.a")
    independent = EvidenceKey("collector.b")
    calls: list[str] = []

    def raise_failure(_context: CollectionContext) -> CollectionOutcome:
        calls.append("collector.a")
        raise RuntimeError("simulated collector failure")

    planner = EvidencePlanner(
        collectors=(
            CollectorSpec(
                collector_id=CollectorId("collector.a"),
                produces=failing,
                collect=raise_failure,
            ),
            _collector("collector.b", independent, calls, _ok(independent)),
        ),
    )

    # Given: one collector raises while an unrelated collector can still produce evidence.
    checks = (_check("check-a", failing), _check("check-b", independent))

    # When: the planner collects both independent branches.
    result = planner.collect(checks)

    # Then: the raised failure becomes an error envelope and the unrelated branch stays ok.
    assert set(calls) == {"collector.a", "collector.b"}
    assert result.envelope_for(failing).health is EvidenceHealth.ERROR
    assert result.envelope_for(failing).reason == "simulated collector failure"
    assert result.envelope_for(independent).health is EvidenceHealth.OK
    assert result.check_health(CheckId("check-a")) is EvidenceHealth.ERROR
    assert result.check_health(CheckId("check-b")) is EvidenceHealth.OK


@pytest.mark.parametrize(
    ("blocked", "expected"),
    [
        (EvidenceEnvelope.error(EvidenceKey("upstream"), reason="timeout"), EvidenceHealth.ERROR),
        (
            EvidenceEnvelope.truncated(
                EvidenceKey("upstream"),
                reason="page budget exhausted",
                metadata=CollectionMetadata(
                    source="fake",
                    items_collected=400,
                    pagination=PaginationMetadata(
                        pages_read=1,
                        max_pages=1,
                        next_link_seen=True,
                    ),
                ),
            ),
            EvidenceHealth.TRUNCATED,
        ),
    ],
)
def test_error_and_truncated_dependencies_cannot_produce_ok_downstream(
    blocked: EvidenceEnvelope,
    expected: EvidenceHealth,
) -> None:
    upstream = EvidenceKey("upstream")
    downstream = EvidenceKey("downstream")
    calls: list[str] = []
    planner = EvidencePlanner(
        collectors=(
            _collector("upstream", upstream, calls, blocked),
            _collector("downstream", downstream, calls, _ok(downstream), depends_on=(upstream,)),
        ),
    )

    # Given: a downstream evidence source depends on unhealthy upstream evidence.
    checks = (_check("dependent-check", downstream),)

    # When: evidence is collected.
    result = planner.collect(checks)

    # Then: downstream collection is skipped and the check cannot appear ok.
    assert calls == ["upstream"]
    assert result.envelope_for(upstream).health is expected
    assert result.envelope_for(downstream).health is EvidenceHealth.UNAVAILABLE
    assert result.check_health(CheckId("dependent-check")) is EvidenceHealth.UNAVAILABLE


def test_unsupported_cloud_marks_evidence_without_calling_collector() -> None:
    key = EvidenceKey("arm.sentinel_rules")
    calls: list[str] = []
    planner = EvidencePlanner(
        collectors=(
            _collector(
                "sentinel.rules",
                key,
                calls,
                _ok(key),
                supported_clouds=(CloudEnvironment.PUBLIC,),
            ),
        ),
        cloud=CloudEnvironment.US_GOV,
    )

    # Given: a collector that does not support the active cloud.
    checks = (_check("sen-analytics-rule-coverage", key),)

    # When: evidence is collected.
    result = planner.collect(checks)

    # Then: no unsupported collector call is attempted and the check is not ok.
    assert calls == []
    assert result.envelope_for(key).health is EvidenceHealth.UNSUPPORTED
    assert result.check_health(CheckId("sen-analytics-rule-coverage")) is EvidenceHealth.UNSUPPORTED


def test_malformed_planner_input_rejects_missing_producer_and_cycles() -> None:
    # Given: a check requiring evidence no registered collector can produce.
    planner = EvidencePlanner(collectors=())

    # When / Then: malformed inputs fail before any misleading success is possible.
    with pytest.raises(CollectionPlanError):
        planner.build_plan((_check("missing", EvidenceKey("missing.evidence")),))

    cyclic_a = EvidenceKey("cycle.a")
    cyclic_b = EvidenceKey("cycle.b")
    with pytest.raises(CollectionPlanError):
        EvidencePlanner(
            collectors=(
                _collector("a", cyclic_a, [], _ok(cyclic_a), depends_on=(cyclic_b,)),
                _collector("b", cyclic_b, [], _ok(cyclic_b), depends_on=(cyclic_a,)),
            ),
        ).build_plan((_check("cycle", cyclic_a),))

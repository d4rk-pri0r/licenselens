from licenselens.collectors.mde import DEMO_MDE_SUMMARY
from licenselens.collectors.secure_score import (
    DEMO_SECURE_SCORE,
    MDO_CONTROL_HINTS,
    extract_control_scores,
    summarize_controls,
)
from licenselens.engine.evaluate import (
    evaluate_mde_onboard_gap,
    evaluate_mdi_sensors,
    evaluate_mdo_p2_policies,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.DEFENDER)


def test_secure_score_demo_matches_mdo_hints():
    controls = extract_control_scores(DEMO_SECURE_SCORE)
    summary = summarize_controls(controls, MDO_CONTROL_HINTS)
    assert summary["matched_count"] >= 2


def test_mdo_demo_is_partial_or_gap():
    controls = extract_control_scores(DEMO_SECURE_SCORE)
    result = evaluate_mdo_p2_policies(
        _check("mdo-p2-policies-default"),
        {"secure_score_controls": controls, "exchange_threat_usable": False},
    )
    assert result.status in {FindingStatus.PARTIAL, FindingStatus.GAP}
    assert result.evidence["matched_controls"] >= 1


def test_mdo_direct_exchange_demo_is_ok_or_partial():
    from licenselens.collectors.exchange import demo_exchange_evidence

    result = evaluate_mdo_p2_policies(
        _check("mdo-p2-policies-default"),
        demo_exchange_evidence(),
    )
    assert result.status in {FindingStatus.OK, FindingStatus.PARTIAL}
    assert result.evidence.get("proxy") is False
    assert result.evidence.get("exchange_direct") is True


def test_mde_demo_is_gap():
    result = evaluate_mde_onboard_gap(
        _check("mde-onboard-gap"),
        {"mde_summary": DEMO_MDE_SUMMARY},
    )
    assert result.status == FindingStatus.GAP
    assert result.evidence["onboarded_machines"] == 40
    assert result.evidence["licensed_units"] == 100


def test_mde_ok_when_coverage_high():
    result = evaluate_mde_onboard_gap(
        _check("mde-onboard-gap"),
        {
            "mde_summary": {
                "onboarded_machines": 95,
                "licensed_units": 100,
                "truncated": False,
                "count_method": "test",
            }
        },
    )
    assert result.status == FindingStatus.OK


def test_mdi_demo_partial_without_controls():
    # Demo score has no MDI-named controls → partial / cannot confirm
    controls = extract_control_scores(DEMO_SECURE_SCORE)
    result = evaluate_mdi_sensors(
        _check("mdi-sensors-missing"),
        {"secure_score_controls": controls},
    )
    assert result.status == FindingStatus.PARTIAL

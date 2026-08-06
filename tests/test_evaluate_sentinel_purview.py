from licenselens.collectors.purview import DEMO_DLP_BUNDLE
from licenselens.collectors.sentinel import DEMO_SENTINEL_RULES, DEMO_SENTINEL_UEBA
from licenselens.engine.evaluate import (
    evaluate_purview_dlp,
    evaluate_sen_analytics_coverage,
    evaluate_sen_ueba,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.SENTINEL)


def test_sen_analytics_demo_partial():
    result = evaluate_sen_analytics_coverage(
        _check("sen-analytics-rule-coverage"),
        {"sentinel_rules": DEMO_SENTINEL_RULES},
    )
    assert result.status == FindingStatus.PARTIAL
    assert result.evidence["enabled_scheduled_or_nrt"] == 2


def test_sen_analytics_ok_dense():
    result = evaluate_sen_analytics_coverage(
        _check("sen-analytics-rule-coverage"),
        {
            "sentinel_rules": {
                "total_rules": 40,
                "enabled_rules": 25,
                "enabled_scheduled_or_nrt": 22,
                "tactic_count": 6,
                "tactics": ["a", "b", "c", "d", "e", "f"],
                "sample_enabled_rules": [],
            }
        },
    )
    assert result.status == FindingStatus.OK


def test_sen_analytics_missing_workspace_error():
    result = evaluate_sen_analytics_coverage(
        _check("sen-analytics-rule-coverage"),
        {"sentinel_workspace_missing": True},
    )
    assert result.status == FindingStatus.ERROR


def test_sen_ueba_demo_gap():
    result = evaluate_sen_ueba(
        _check("sen-ueba-not-enabled"),
        {"sentinel_ueba": DEMO_SENTINEL_UEBA},
    )
    assert result.status == FindingStatus.GAP


def test_sen_ueba_enabled_ok():
    result = evaluate_sen_ueba(
        _check("sen-ueba-not-enabled"),
        {"sentinel_ueba": {**DEMO_SENTINEL_UEBA, "ueba_enabled": True}},
    )
    assert result.status == FindingStatus.OK


def test_purview_dlp_demo_gap():
    result = evaluate_purview_dlp(
        _check("pur-dlp-not-enforced"),
        {"purview_dlp": DEMO_DLP_BUNDLE},
    )
    assert result.status == FindingStatus.GAP

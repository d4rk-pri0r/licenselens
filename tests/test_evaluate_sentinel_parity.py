"""WS3-C: sen-rule-telemetry-parity evaluator."""

from __future__ import annotations

from licenselens.auth import AuthContext, AuthMode
from licenselens.catalog.telemetry import load_telemetry_expectations
from licenselens.engine.evaluate import evaluate_sen_rule_telemetry_parity
from licenselens.engine.registry import default_registry
from licenselens.engine.runner import run_scan
from licenselens.models import CheckDefinition, FindingStatus, Workload
from licenselens.schema_contracts import EvaluationMode


def _check() -> CheckDefinition:
    return CheckDefinition(
        id="sen-rule-telemetry-parity",
        title="parity",
        workload=Workload.SENTINEL,
    )


def _catalog() -> dict:
    return load_telemetry_expectations()


def _usage(tables: dict, *, mode: str = "query", incomplete: bool = False) -> dict:
    return {
        "tables": tables,
        "window_days": 7,
        "mode": mode,
        "required_surface_incomplete": incomplete,
    }


def _row(mb: float = 1.0, rows: int = 5) -> dict:
    return {"total_mb": mb, "last_seen": "2026-09-01T00:00:00Z", "rows": rows}


def _rule(name: str, query: str, *, enabled: bool = True) -> dict:
    return {
        "query": query,
        "kind": "Scheduled",
        "enabled": enabled,
        "tactics": ["InitialAccess"],
        "displayName": name,
    }


def _evidence(*, rules: list[dict], tables: dict, owned: list[str] | None = None) -> dict:
    return {
        "sentinel_rules": {
            "rules_detail": rules,
            "enabled_scheduled_or_nrt": sum(1 for r in rules if r.get("enabled")),
        },
        "la_usage_by_table": _usage(tables),
        "telemetry_expectations": _catalog(),
        "owned_capabilities": owned or ["conditional_access", "defender_endpoint_p2"],
    }


def test_indeterminate_never_dead() -> None:
    result = evaluate_sen_rule_telemetry_parity(
        _check(),
        _evidence(
            rules=[
                _rule("parser", "_Im_Authentication | take 1"),
                _rule("empty", ""),
                _rule("live", "SigninLogs | take 1"),
            ],
            tables={"SigninLogs": _row()},
        ),
    )
    names = [row["name"] for row in result.evidence["dead_rules"]]
    assert "parser" not in names
    assert "empty" not in names
    assert result.evidence["indeterminate_rules"] >= 1


def test_small_sample_never_ok() -> None:
    result = evaluate_sen_rule_telemetry_parity(
        _check(),
        _evidence(
            rules=[
                _rule("a", "SigninLogs | take 1"),
                _rule("b", "SigninLogs | take 1"),
            ],
            tables={"SigninLogs": _row()},
        ),
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK


def test_dead_ratio_gap() -> None:
    rules = [
        _rule("live-1", "SigninLogs | take 1"),
        _rule("dead-1", "DeviceProcessEvents | take 1"),
        _rule("dead-2", "DeviceProcessEvents | take 1"),
        _rule("live-2", "SigninLogs | take 1"),
    ]
    result = evaluate_sen_rule_telemetry_parity(
        _check(),
        _evidence(rules=rules, tables={"SigninLogs": _row()}),
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence["dead_rule_ratio"] >= 0.25
    assert any(row["name"] == "dead-1" for row in result.evidence["dead_rules"])


def test_all_live_and_watched_ok() -> None:
    rules = [
        _rule("a", "SigninLogs | take 1"),
        _rule("b", "DeviceProcessEvents | take 1"),
        _rule("c", "SigninLogs | take 1"),
    ]
    result = evaluate_sen_rule_telemetry_parity(
        _check(),
        _evidence(
            rules=rules,
            tables={"SigninLogs": _row(), "DeviceProcessEvents": _row()},
            owned=["conditional_access"],
        ),
    )
    assert result.status is FindingStatus.OK


def test_empty_query_is_indeterminate_not_dead() -> None:
    result = evaluate_sen_rule_telemetry_parity(
        _check(),
        _evidence(
            rules=[_rule("blank", "   "), _rule("live", "SigninLogs | take 1")] * 2,
            tables={"SigninLogs": _row()},
        ),
    )
    assert all(row["name"] != "blank" for row in result.evidence["dead_rules"])


def test_registered_as_direct() -> None:
    entry = default_registry().evaluators["sen-rule-telemetry-parity"]
    assert entry.evaluation_mode is EvaluationMode.DIRECT


def test_parity_missing_data_is_partial() -> None:
    result = evaluate_sen_rule_telemetry_parity(
        _check(),
        {
            "la_usage_by_table": {},
            "sentinel_rules": {},
            "telemetry_expectations": {},
            "owned_capabilities": ["conditional_access"],
        },
    )
    assert result.status is FindingStatus.PARTIAL
    assert "sen-rule-telemetry-parity" in _check().id


def test_demo_parity_is_gap_named_dead_rule() -> None:
    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    by_id = {f.check_id: f for f in result.findings}
    finding = by_id["sen-rule-telemetry-parity"]
    assert finding.status is FindingStatus.GAP
    names = [row["name"] for row in finding.evidence.get("dead_rules") or []]
    assert "Demo rare process" in names
    missing = next(
        row["missing_tables"]
        for row in finding.evidence["dead_rules"]
        if row["name"] == "Demo rare process"
    )
    assert "DeviceProcessEvents" in missing


def test_after_overlay_parity_is_partial_not_ok() -> None:
    result = run_scan(
        AuthContext(mode=AuthMode.DRY_RUN),
        dry_run=True,
        demo_scenario="after",
    )
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["sen-rule-telemetry-parity"].status is FindingStatus.GAP
    assert by_id["sen-rule-telemetry-parity"].status is not FindingStatus.OK

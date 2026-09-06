"""WS3-B: telemetry ingestion + Entra diagnostics proxy evaluators."""

from __future__ import annotations

from licenselens.auth import AuthContext, AuthMode
from licenselens.catalog.telemetry import load_telemetry_expectations
from licenselens.engine.evaluate import (
    evaluate_sen_entra_diagnostics_routed,
    evaluate_sen_telemetry_ingestion_coverage,
)
from licenselens.engine.registry import default_registry
from licenselens.engine.runner import run_scan
from licenselens.models import PROXY_CHECK_IDS, CheckDefinition, FindingStatus, Workload
from licenselens.schema_contracts import EvaluationMode


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.SENTINEL)


def _catalog() -> dict:
    return load_telemetry_expectations()


def _usage(tables: dict, *, mode: str = "query", incomplete: bool = False) -> dict:
    return {
        "tables": tables,
        "window_days": 7,
        "workspace_customer_id": "00000000-0000-0000-0000-000000000000",
        "truncated": False,
        "mode": mode,
        "required_surface_incomplete": incomplete,
    }


def _row(mb: float = 1.0, rows: int = 5) -> dict:
    return {"total_mb": mb, "last_seen": "2026-09-01T00:00:00Z", "rows": rows}


# ---------------------------------------------------------------------------
# Ingestion coverage
# ---------------------------------------------------------------------------
def test_ingestion_empty_in_scope_partial() -> None:
    result = evaluate_sen_telemetry_ingestion_coverage(
        _check("sen-telemetry-ingestion-coverage"),
        {
            "la_usage_by_table": _usage({"SigninLogs": _row()}),
            "telemetry_expectations": _catalog(),
            "owned_capabilities": ["microsoft_sentinel"],
        },
    )
    assert result.status is FindingStatus.PARTIAL


def test_ingestion_zero_core_gap() -> None:
    result = evaluate_sen_telemetry_ingestion_coverage(
        _check("sen-telemetry-ingestion-coverage"),
        {
            "la_usage_by_table": _usage({"SigninLogs": _row()}),
            "telemetry_expectations": _catalog(),
            "owned_capabilities": ["defender_endpoint_p2", "conditional_access"],
        },
    )
    assert result.status is FindingStatus.GAP
    assert "defender_endpoint_p2" in result.evidence["capabilities"]
    assert result.evidence["capabilities"]["defender_endpoint_p2"]["missing_core"]


def test_ingestion_some_missing_partial() -> None:
    tables = {
        "SigninLogs": _row(),
        "DeviceEvents": _row(),
        "DeviceProcessEvents": _row(),
        "DeviceNetworkEvents": _row(),
    }
    result = evaluate_sen_telemetry_ingestion_coverage(
        _check("sen-telemetry-ingestion-coverage"),
        {
            "la_usage_by_table": _usage(tables),
            "telemetry_expectations": _catalog(),
            "owned_capabilities": ["defender_endpoint_p2", "conditional_access"],
        },
    )
    assert result.status is FindingStatus.PARTIAL
    missing = result.evidence["capabilities"]["defender_endpoint_p2"]["missing_core"]
    assert "DeviceLogonEvents" in missing


def test_ingestion_all_cores_ok() -> None:
    tables = {
        "SigninLogs": _row(),
        "DeviceEvents": _row(),
        "DeviceProcessEvents": _row(),
        "DeviceNetworkEvents": _row(),
        "DeviceLogonEvents": _row(),
    }
    result = evaluate_sen_telemetry_ingestion_coverage(
        _check("sen-telemetry-ingestion-coverage"),
        {
            "la_usage_by_table": _usage(tables),
            "telemetry_expectations": _catalog(),
            "owned_capabilities": ["defender_endpoint_p2", "conditional_access"],
        },
    )
    assert result.status is FindingStatus.OK


def test_ingestion_table_list_caps_ok_at_partial() -> None:
    tables = {
        "SigninLogs": {"total_mb": 0.0, "last_seen": None, "rows": 0},
        "DeviceEvents": {"total_mb": 0.0, "last_seen": None, "rows": 0},
        "DeviceProcessEvents": {"total_mb": 0.0, "last_seen": None, "rows": 0},
        "DeviceNetworkEvents": {"total_mb": 0.0, "last_seen": None, "rows": 0},
        "DeviceLogonEvents": {"total_mb": 0.0, "last_seen": None, "rows": 0},
    }
    result = evaluate_sen_telemetry_ingestion_coverage(
        _check("sen-telemetry-ingestion-coverage"),
        {
            "la_usage_by_table": _usage(tables, mode="table_list_only", incomplete=True),
            "telemetry_expectations": _catalog(),
            "owned_capabilities": ["defender_endpoint_p2", "conditional_access"],
        },
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence.get("required_surface_incomplete") is True


def test_ingestion_zero_row_table_not_seen() -> None:
    tables = {
        "SigninLogs": _row(),
        "DeviceEvents": {"total_mb": 0.0, "last_seen": None, "rows": 0},
        "DeviceProcessEvents": _row(),
        "DeviceNetworkEvents": _row(),
        "DeviceLogonEvents": _row(),
    }
    result = evaluate_sen_telemetry_ingestion_coverage(
        _check("sen-telemetry-ingestion-coverage"),
        {
            "la_usage_by_table": _usage(tables),
            "telemetry_expectations": _catalog(),
            "owned_capabilities": ["defender_endpoint_p2", "conditional_access"],
        },
    )
    assert result.status is FindingStatus.PARTIAL
    assert "DeviceEvents" in result.evidence["capabilities"]["defender_endpoint_p2"]["missing_core"]


# ---------------------------------------------------------------------------
# Entra diagnostics proxy
# ---------------------------------------------------------------------------
def test_entra_identity_protection_owned_no_risk_tables_gap() -> None:
    result = evaluate_sen_entra_diagnostics_routed(
        _check("sen-entra-diagnostics-routed"),
        {
            "la_usage_by_table": _usage({"SigninLogs": _row()}),
            "owned_capabilities": ["identity_protection", "microsoft_sentinel"],
        },
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence.get("proxy") is True


def test_entra_risk_tables_present_partial_never_ok() -> None:
    result = evaluate_sen_entra_diagnostics_routed(
        _check("sen-entra-diagnostics-routed"),
        {
            "la_usage_by_table": _usage(
                {
                    "SigninLogs": _row(),
                    "AADUserRiskEvents": _row(),
                    "AADRiskyUsers": _row(),
                }
            ),
            "owned_capabilities": ["identity_protection"],
        },
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.evidence.get("proxy") is True


def test_entra_identity_protection_not_owned_partial() -> None:
    result = evaluate_sen_entra_diagnostics_routed(
        _check("sen-entra-diagnostics-routed"),
        {
            "la_usage_by_table": _usage({"SigninLogs": _row()}),
            "owned_capabilities": ["microsoft_sentinel"],
        },
    )
    assert result.status is FindingStatus.PARTIAL


def test_entra_is_in_proxy_check_ids() -> None:
    assert "sen-entra-diagnostics-routed" in PROXY_CHECK_IDS


def test_entra_registered_as_proxy() -> None:
    entry = default_registry().evaluators["sen-entra-diagnostics-routed"]
    assert entry.evaluation_mode is EvaluationMode.PROXY


def test_ingestion_registered_as_direct() -> None:
    entry = default_registry().evaluators["sen-telemetry-ingestion-coverage"]
    assert entry.evaluation_mode is EvaluationMode.DIRECT


# ---------------------------------------------------------------------------
# Demo / after overlay
# ---------------------------------------------------------------------------
def test_demo_ingestion_is_gap() -> None:
    result = run_scan(AuthContext(mode=AuthMode.DRY_RUN), dry_run=True)
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["sen-telemetry-ingestion-coverage"].status is FindingStatus.GAP
    assert by_id["sen-entra-diagnostics-routed"].status is FindingStatus.PARTIAL
    assert by_id["sen-entra-diagnostics-routed"].evaluation_mode is EvaluationMode.PROXY


def test_after_overlay_ingestion_not_gap() -> None:
    result = run_scan(
        AuthContext(mode=AuthMode.DRY_RUN),
        dry_run=True,
        demo_scenario="after",
    )
    by_id = {f.check_id: f for f in result.findings}
    assert by_id["sen-telemetry-ingestion-coverage"].status is not FindingStatus.GAP

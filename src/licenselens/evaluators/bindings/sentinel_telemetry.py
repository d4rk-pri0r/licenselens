"""Typed evaluator registrations for Sentinel telemetry checks."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.sentinel_telemetry import (
    evaluate_sen_entra_diagnostics_routed,
    evaluate_sen_telemetry_ingestion_coverage,
)
from licenselens.schema_contracts import EvaluationMode


def register_sentinel_telemetry(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.sentinel_telemetry")
    try:
        catalog.add_evaluator(
            check_id="sen-telemetry-ingestion-coverage",
            evaluate=evaluate_sen_telemetry_ingestion_coverage,
            input_models=("la_usage_by_table", "telemetry_expectations"),
            collector_id="la_usage_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="sen-entra-diagnostics-routed",
            evaluate=evaluate_sen_entra_diagnostics_routed,
            input_models=("la_usage_by_table",),
            collector_id="la_usage_collector",
            evaluation_mode=EvaluationMode.PROXY,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.sentinel_telemetry")

"""Typed evaluator registrations for Sentinel rule↔telemetry parity."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.sentinel_parity import evaluate_sen_rule_telemetry_parity
from licenselens.schema_contracts import EvaluationMode


def register_sentinel_parity(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.sentinel_parity")
    try:
        catalog.add_evaluator(
            check_id="sen-rule-telemetry-parity",
            evaluate=evaluate_sen_rule_telemetry_parity,
            input_models=("sentinel_rules", "la_usage_by_table", "telemetry_expectations"),
            collector_id="sentinel_analytics",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.sentinel_parity")

"""Typed evaluator registrations for sentinel_extended."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.sentinel_extended import (
    evaluate_sen_automation_rules,
    evaluate_sen_data_connectors,
    evaluate_sen_log_analytics_retention,
)
from licenselens.schema_contracts import EvaluationMode


def register_sentinel_extended(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.sentinel_extended")
    try:
        catalog.add_evaluator(
            check_id="sen-automation-rules",
            evaluate=evaluate_sen_automation_rules,
            input_models=("sentinel_automation_rules",),
            collector_id="sentinel_automation_rules_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="sen-data-connectors",
            evaluate=evaluate_sen_data_connectors,
            input_models=("sentinel_data_connectors",),
            collector_id="sentinel_data_connectors_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="sen-log-analytics-retention",
            evaluate=evaluate_sen_log_analytics_retention,
            input_models=("sentinel_workspace",),
            collector_id="sentinel_workspace_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.sentinel_extended")

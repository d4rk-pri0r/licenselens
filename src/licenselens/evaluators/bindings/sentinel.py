"""Typed evaluator registrations for sentinel."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.sentinel import (
    evaluate_sen_analytics_coverage,
    evaluate_sen_ueba,
)
from licenselens.schema_contracts import EvaluationMode


def register_sentinel(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.sentinel")
    try:
        catalog.add_evaluator(
            check_id="sen-analytics-rule-coverage",
            evaluate=evaluate_sen_analytics_coverage,
            input_models=("sentinel_rules",),
            collector_id="sentinel_analytics",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="sen-ueba-not-enabled",
            evaluate=evaluate_sen_ueba,
            input_models=("sentinel_ueba",),
            collector_id="sentinel_ueba_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.sentinel")

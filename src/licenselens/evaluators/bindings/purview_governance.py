"""Typed evaluator registrations for purview_governance."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.purview_governance import (
    evaluate_pur_retention_policy_coverage,
    evaluate_pur_sensitivity_auto_labeling,
    evaluate_pur_sensitivity_labels_published,
)
from licenselens.schema_contracts import EvaluationMode


def register_purview_governance(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.purview_governance")
    try:
        catalog.add_evaluator(
            check_id="pur-retention-policy-coverage",
            evaluate=evaluate_pur_retention_policy_coverage,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pur-sensitivity-auto-labeling",
            evaluate=evaluate_pur_sensitivity_auto_labeling,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pur-sensitivity-labels-published",
            evaluate=evaluate_pur_sensitivity_labels_published,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.purview_governance")


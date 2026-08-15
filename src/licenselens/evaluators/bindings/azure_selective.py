"""Typed evaluator registrations for azure_selective."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.azure_selective import (
    evaluate_az_cspm_out_of_scope,
    evaluate_az_defender_plan_enabled,
)
from licenselens.schema_contracts import EvaluationMode


def register_azure_selective(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.azure_selective")
    try:
        catalog.add_evaluator(
            check_id="az-cspm-out-of-scope",
            evaluate=evaluate_az_cspm_out_of_scope,
            input_models=('break_glass_principal_ids',),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
        catalog.add_evaluator(
            check_id="az-defender-plan-enabled",
            evaluate=evaluate_az_defender_plan_enabled,
            input_models=('defender_for_cloud_pricings',),
            collector_id="defender_pricings_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.azure_selective")


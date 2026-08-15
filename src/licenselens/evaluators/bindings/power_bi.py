"""Typed evaluator registrations for power_bi."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.power_bi import (
    evaluate_pbi_external_invite_disabled,
    evaluate_pbi_guest_access_disabled,
    evaluate_pbi_premium_capacity_governance,
    evaluate_pbi_publish_to_web_disabled,
    evaluate_pbi_python_r_visuals_disabled,
    evaluate_pbi_resource_key_auth_blocked,
    evaluate_pbi_sensitivity_labels_enabled,
    evaluate_pbi_sp_api_restricted,
    evaluate_pbi_sp_profiles_disabled,
)
from licenselens.schema_contracts import EvaluationMode


def register_power_bi(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.power_bi")
    try:
        catalog.add_evaluator(
            check_id="pbi-premium-capacity-governance",
            evaluate=evaluate_pbi_premium_capacity_governance,
            input_models=("break_glass_principal_ids",),
            collector_id="manual_identity",
            evaluation_mode=EvaluationMode.MANUAL,
        )
        catalog.add_evaluator(
            check_id="pbi-external-invite-disabled",
            evaluate=evaluate_pbi_external_invite_disabled,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pbi-guest-access-disabled",
            evaluate=evaluate_pbi_guest_access_disabled,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pbi-publish-to-web-disabled",
            evaluate=evaluate_pbi_publish_to_web_disabled,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pbi-python-r-visuals-disabled",
            evaluate=evaluate_pbi_python_r_visuals_disabled,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pbi-resource-key-auth-blocked",
            evaluate=evaluate_pbi_resource_key_auth_blocked,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pbi-sensitivity-labels-enabled",
            evaluate=evaluate_pbi_sensitivity_labels_enabled,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pbi-sp-api-restricted",
            evaluate=evaluate_pbi_sp_api_restricted,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pbi-sp-profiles-disabled",
            evaluate=evaluate_pbi_sp_profiles_disabled,
            input_models=('power_data_bundle',),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.power_bi")


"""Typed evaluator registrations for power_platform_tenant."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.power_platform_tenant import (
    evaluate_pp_env_creation_admin_only,
    evaluate_pp_pages_creation_admin_only,
    evaluate_pp_share_with_everyone_disabled,
    evaluate_pp_trial_creation_admin_only,
)
from licenselens.schema_contracts import EvaluationMode


def register_power_platform_tenant(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.power_platform_tenant")
    try:
        catalog.add_evaluator(
            check_id="pp-env-creation-admin-only",
            evaluate=evaluate_pp_env_creation_admin_only,
            input_models=("power_data_bundle",),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pp-pages-creation-admin-only",
            evaluate=evaluate_pp_pages_creation_admin_only,
            input_models=("power_data_bundle",),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pp-share-with-everyone-disabled",
            evaluate=evaluate_pp_share_with_everyone_disabled,
            input_models=("power_data_bundle",),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pp-trial-creation-admin-only",
            evaluate=evaluate_pp_trial_creation_admin_only,
            input_models=("power_data_bundle",),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.power_platform_tenant")

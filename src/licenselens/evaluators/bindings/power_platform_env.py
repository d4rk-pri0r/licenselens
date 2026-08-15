"""Typed evaluator registrations for power_platform_env."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.power_platform_env import (
    evaluate_pp_dlp_all_environments,
    evaluate_pp_tenant_isolation_enabled,
)
from licenselens.schema_contracts import EvaluationMode


def register_power_platform_env(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.power_platform_env")
    try:
        catalog.add_evaluator(
            check_id="pp-dlp-all-environments",
            evaluate=evaluate_pp_dlp_all_environments,
            input_models=("power_data_bundle",),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="pp-tenant-isolation-enabled",
            evaluate=evaluate_pp_tenant_isolation_enabled,
            input_models=("power_data_bundle",),
            collector_id="power_data_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.power_platform_env")

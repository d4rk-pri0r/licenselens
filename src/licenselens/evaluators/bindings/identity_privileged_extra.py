"""Typed evaluator registrations for identity_privileged_extra."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_privileged_extra import (
    evaluate_ga_count_bounds,
    evaluate_ga_finer_roles,
    evaluate_password_never_expire,
    evaluate_priv_cloud_only,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_privileged_extra(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_privileged_extra")
    try:
        catalog.add_evaluator(
            check_id="id-ga-count-bounds",
            evaluate=evaluate_ga_count_bounds,
            input_models=('role_assignments',),
            collector_id="graph_pim",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-ga-finer-roles",
            evaluate=evaluate_ga_finer_roles,
            input_models=('role_assignments',),
            collector_id="graph_pim",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-password-never-expire",
            evaluate=evaluate_password_never_expire,
            input_models=('domains',),
            collector_id="graph_domains",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-priv-cloud-only",
            evaluate=evaluate_priv_cloud_only,
            input_models=('role_assignments', 'principal_directory',),
            collector_id="graph_signins_roles",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_privileged_extra")


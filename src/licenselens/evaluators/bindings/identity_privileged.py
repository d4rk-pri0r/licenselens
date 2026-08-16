"""Typed evaluator registrations for identity_privileged."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_privileged import (
    evaluate_dormant_privileged,
    evaluate_pim_unused,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_privileged(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_privileged")
    try:
        catalog.add_evaluator(
            check_id="id-dormant-privileged",
            evaluate=evaluate_dormant_privileged,
            input_models=(
                "role_assignments",
                "recent_signin_user_ids",
                "principal_directory",
            ),
            collector_id="graph_signins_roles",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-pim-unused",
            evaluate=evaluate_pim_unused,
            input_models=(
                "role_assignments",
                "role_eligibilities",
                "break_glass_principal_ids",
            ),
            collector_id="graph_pim",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_privileged")

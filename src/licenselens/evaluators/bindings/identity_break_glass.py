"""Typed evaluator registrations for identity_break_glass."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_break_glass import evaluate_break_glass_exclusion
from licenselens.schema_contracts import EvaluationMode


def register_identity_break_glass(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_break_glass")
    try:
        catalog.add_evaluator(
            check_id="id-break-glass-exclusion",
            evaluate=evaluate_break_glass_exclusion,
            input_models=(
                "ca_policies",
                "role_assignments",
                "role_eligibilities",
                "break_glass_principal_ids",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_break_glass")

"""Typed evaluator registrations for identity_risk."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_risk import (
    evaluate_idprotect_off,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_risk(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_risk")
    try:
        catalog.add_evaluator(
            check_id="id-idprotect-off",
            evaluate=evaluate_idprotect_off,
            input_models=('ca_policies',),
            collector_id="graph_identity_protection",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_risk")


"""Typed evaluator registrations for identity_ca_risk."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_ca_risk import (
    evaluate_ca_high_risk_signins,
    evaluate_ca_high_risk_users,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_ca_risk(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_ca_risk")
    try:
        catalog.add_evaluator(
            check_id="id-ca-high-risk-signins",
            evaluate=evaluate_ca_high_risk_signins,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_identity_protection",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-ca-high-risk-users",
            evaluate=evaluate_ca_high_risk_users,
            input_models=(
                "ca_policies",
                "break_glass_principal_ids",
            ),
            collector_id="graph_identity_protection",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_ca_risk")

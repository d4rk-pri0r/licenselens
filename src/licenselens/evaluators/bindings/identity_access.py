"""Typed evaluator registrations for identity_access."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_access import (
    evaluate_ca_priv_gaps,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_access(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_access")
    try:
        catalog.add_evaluator(
            check_id="id-ca-priv-gaps",
            evaluate=evaluate_ca_priv_gaps,
            input_models=(
                "ca_policies",
                "role_assignments",
            ),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_access")

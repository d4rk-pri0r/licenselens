"""Typed evaluator registrations for identity_auth_methods."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_auth_methods import (
    evaluate_auth_authenticator_context,
    evaluate_auth_methods_migration,
    evaluate_auth_weak_methods_disabled,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_auth_methods(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_auth_methods")
    try:
        catalog.add_evaluator(
            check_id="id-auth-authenticator-context",
            evaluate=evaluate_auth_authenticator_context,
            input_models=("auth_methods_bundle",),
            collector_id="graph_auth_methods",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-auth-methods-migration",
            evaluate=evaluate_auth_methods_migration,
            input_models=("auth_methods_bundle",),
            collector_id="graph_auth_methods",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-auth-weak-methods-disabled",
            evaluate=evaluate_auth_weak_methods_disabled,
            input_models=("auth_methods_bundle",),
            collector_id="graph_auth_methods",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_auth_methods")

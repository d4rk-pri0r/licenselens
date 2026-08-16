"""Typed evaluator registrations for identity_governance."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_governance import (
    evaluate_access_reviews_scope,
    evaluate_access_reviews_unused,
    evaluate_entitlement_access_packages,
    evaluate_security_defaults_on,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_governance(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_governance")
    try:
        catalog.add_evaluator(
            check_id="id-access-reviews-unused",
            evaluate=evaluate_access_reviews_unused,
            input_models=("access_review_definitions",),
            collector_id="graph_access_reviews",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-access-reviews-scope",
            evaluate=evaluate_access_reviews_scope,
            input_models=("access_review_definitions", "access_review_instances"),
            collector_id="graph_access_reviews",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-security-defaults-on",
            evaluate=evaluate_security_defaults_on,
            input_models=("security_defaults_policy", "ca_policies"),
            collector_id="graph_security_defaults",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-entitlement-access-packages",
            evaluate=evaluate_entitlement_access_packages,
            input_models=("access_packages",),
            collector_id="graph_entitlement_management",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_governance")

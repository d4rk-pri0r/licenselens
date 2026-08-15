"""Typed evaluator registrations for identity_apps_credentials."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_apps_credentials import (
    evaluate_app_certificate_lifetime,
    evaluate_app_expiring_credentials,
    evaluate_app_ownerless_or_stale,
    evaluate_app_password_lifetime,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_apps_credentials(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_apps_credentials")
    try:
        catalog.add_evaluator(
            check_id="id-app-certificate-lifetime",
            evaluate=evaluate_app_certificate_lifetime,
            input_models=('applications_bundle',),
            collector_id="graph_applications",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-app-expiring-credentials",
            evaluate=evaluate_app_expiring_credentials,
            input_models=('applications_bundle',),
            collector_id="graph_applications",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-app-ownerless-or-stale",
            evaluate=evaluate_app_ownerless_or_stale,
            input_models=('applications_bundle',),
            collector_id="graph_applications",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-app-password-lifetime",
            evaluate=evaluate_app_password_lifetime,
            input_models=('applications_bundle',),
            collector_id="graph_applications",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_apps_credentials")


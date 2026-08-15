"""Typed evaluator registrations for identity_apps_consent."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_apps_consent import (
    evaluate_app_admin_consent_workflow,
    evaluate_app_password_addition_blocked,
    evaluate_app_registration_admin_only,
    evaluate_app_risky_delegated_consent,
    evaluate_app_user_consent_restricted,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_apps_consent(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_apps_consent")
    try:
        catalog.add_evaluator(
            check_id="id-app-admin-consent-workflow",
            evaluate=evaluate_app_admin_consent_workflow,
            input_models=("admin_consent_request_policy",),
            collector_id="graph_authorization",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-app-password-addition-blocked",
            evaluate=evaluate_app_password_addition_blocked,
            input_models=("ca_policies",),
            collector_id="graph_ca",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-app-registration-admin-only",
            evaluate=evaluate_app_registration_admin_only,
            input_models=("authorization_policy",),
            collector_id="graph_authorization",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-app-risky-delegated-consent",
            evaluate=evaluate_app_risky_delegated_consent,
            input_models=("applications_bundle",),
            collector_id="graph_applications",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-app-user-consent-restricted",
            evaluate=evaluate_app_user_consent_restricted,
            input_models=("authorization_policy",),
            collector_id="graph_authorization",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_apps_consent")

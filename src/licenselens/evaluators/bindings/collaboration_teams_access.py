"""Typed evaluator registrations for collaboration_teams_access."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.collaboration_teams_access import (
    evaluate_teams_email_integration_disabled,
    evaluate_teams_external_access_per_domain,
    evaluate_teams_guest_access_restricted,
    evaluate_teams_unmanaged_inbound_blocked,
    evaluate_teams_unmanaged_outbound_blocked,
)
from licenselens.schema_contracts import EvaluationMode


def register_collaboration_teams_access(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.collaboration_teams_access")
    try:
        catalog.add_evaluator(
            check_id="teams-email-integration-disabled",
            evaluate=evaluate_teams_email_integration_disabled,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-external-access-per-domain",
            evaluate=evaluate_teams_external_access_per_domain,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-guest-access-restricted",
            evaluate=evaluate_teams_guest_access_restricted,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-unmanaged-inbound-blocked",
            evaluate=evaluate_teams_unmanaged_inbound_blocked,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="teams-unmanaged-outbound-blocked",
            evaluate=evaluate_teams_unmanaged_outbound_blocked,
            input_models=("collaboration_bundle",),
            collector_id="collaboration_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.collaboration_teams_access")

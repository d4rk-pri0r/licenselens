"""Typed evaluator registrations for identity_guests."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.identity_guests import (
    evaluate_cross_tenant_defaults,
    evaluate_cross_tenant_mfa_trust,
    evaluate_guest_directory_access_limited,
    evaluate_guest_invite_domains,
    evaluate_guest_inviter_restricted,
)
from licenselens.schema_contracts import EvaluationMode


def register_identity_guests(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.identity_guests")
    try:
        catalog.add_evaluator(
            check_id="id-cross-tenant-mfa-trust",
            evaluate=evaluate_cross_tenant_mfa_trust,
            input_models=("guests_bundle",),
            collector_id="graph_guests",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-cross-tenant-defaults",
            evaluate=evaluate_cross_tenant_defaults,
            input_models=("guests_bundle",),
            collector_id="graph_guests",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-guest-directory-access-limited",
            evaluate=evaluate_guest_directory_access_limited,
            input_models=("authorization_policy",),
            collector_id="graph_authorization",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="id-guest-invite-domains",
            evaluate=evaluate_guest_invite_domains,
            input_models=(
                "approved_guest_domains",
                "guests_bundle",
            ),
            collector_id="graph_guests",
            evaluation_mode=EvaluationMode.MANUAL,
        )
        catalog.add_evaluator(
            check_id="id-guest-inviter-restricted",
            evaluate=evaluate_guest_inviter_restricted,
            input_models=("authorization_policy",),
            collector_id="graph_authorization",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.identity_guests")

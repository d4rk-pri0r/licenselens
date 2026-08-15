"""Typed evaluator registrations for exchange_mailflow."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.exchange_mailflow import (
    evaluate_exo_external_sender_warnings,
    evaluate_exo_forwarding_external_disabled,
    evaluate_exo_mailbox_audit_enabled,
    evaluate_exo_sharing_calendar_not_all_domains,
    evaluate_exo_sharing_contact_not_all_domains,
    evaluate_exo_smtp_auth_disabled,
)
from licenselens.schema_contracts import EvaluationMode


def register_exchange_mailflow(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.exchange_mailflow")
    try:
        catalog.add_evaluator(
            check_id="exo-external-sender-warnings",
            evaluate=evaluate_exo_external_sender_warnings,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-forwarding-external-disabled",
            evaluate=evaluate_exo_forwarding_external_disabled,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-mailbox-audit-enabled",
            evaluate=evaluate_exo_mailbox_audit_enabled,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-sharing-calendar-not-all-domains",
            evaluate=evaluate_exo_sharing_calendar_not_all_domains,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-sharing-contact-not-all-domains",
            evaluate=evaluate_exo_sharing_contact_not_all_domains,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-smtp-auth-disabled",
            evaluate=evaluate_exo_smtp_auth_disabled,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.exchange_mailflow")

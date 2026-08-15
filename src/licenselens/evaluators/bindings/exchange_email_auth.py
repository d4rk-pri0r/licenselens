"""Typed evaluator registrations for exchange_email_auth."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.evaluators.exchange_email_auth import (
    evaluate_exo_dkim_enabled,
    evaluate_exo_dmarc_agency_contact,
    evaluate_exo_dmarc_federal_contact,
    evaluate_exo_dmarc_published,
    evaluate_exo_dmarc_reject,
    evaluate_exo_spf_published,
)
from licenselens.schema_contracts import EvaluationMode


def register_exchange_email_auth(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.exchange_email_auth")
    try:
        catalog.add_evaluator(
            check_id="exo-dkim-enabled",
            evaluate=evaluate_exo_dkim_enabled,
            input_models=("exchange_bundle",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-dmarc-agency-contact",
            evaluate=evaluate_exo_dmarc_agency_contact,
            input_models=("dns_records",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-dmarc-federal-contact",
            evaluate=evaluate_exo_dmarc_federal_contact,
            input_models=("dns_records",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-dmarc-published",
            evaluate=evaluate_exo_dmarc_published,
            input_models=("dns_records",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-dmarc-reject",
            evaluate=evaluate_exo_dmarc_reject,
            input_models=("dns_records",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
        catalog.add_evaluator(
            check_id="exo-spf-published",
            evaluate=evaluate_exo_spf_published,
            input_models=("dns_records",),
            collector_id="exchange_collector",
            evaluation_mode=EvaluationMode.DIRECT,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.exchange_email_auth")

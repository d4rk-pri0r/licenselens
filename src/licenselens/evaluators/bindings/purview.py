"""Typed evaluator registrations for purview."""
from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.engine.registry import Backend
from licenselens.evaluators.purview import (
    evaluate_purview_dlp,
)
from licenselens.schema_contracts import EvaluationMode


def register_purview(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.purview")
    try:
        catalog.add_evaluator(
            check_id="pur-dlp-not-enforced",
            evaluate=evaluate_purview_dlp,
            input_models=('purview_dlp',),
            collector_id="purview_dlp_collector",
            evaluation_mode=EvaluationMode.PROXY,
            backend=Backend.PROXY,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.purview")


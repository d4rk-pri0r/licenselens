"""Typed evaluator registrations for purview."""

from __future__ import annotations

from licenselens.engine.registration import RegistrationCatalog
from licenselens.engine.registry import Backend
from licenselens.evaluators.purview import (
    evaluate_pur_ediscovery_readiness,
    evaluate_pur_insider_risk_readiness,
    evaluate_purview_dlp,
)
from licenselens.schema_contracts import EvaluationMode


def register_purview(catalog: RegistrationCatalog) -> None:
    catalog.enter_module("licenselens.evaluators.bindings.purview")
    try:
        catalog.add_evaluator(
            check_id="pur-dlp-not-enforced",
            evaluate=evaluate_purview_dlp,
            input_models=("purview_dlp",),
            collector_id="purview_dlp_collector",
            evaluation_mode=EvaluationMode.DIRECT_WITH_PROXY_FALLBACK,
            backend=Backend.PROXY,
        )
        catalog.add_evaluator(
            check_id="pur-ediscovery-readiness",
            evaluate=evaluate_pur_ediscovery_readiness,
            input_models=("purview_ediscovery",),
            collector_id="graph_purview_ediscovery",
            evaluation_mode=EvaluationMode.DIRECT,
            backend=Backend.GRAPH,
        )
        catalog.add_evaluator(
            check_id="pur-insider-risk-readiness",
            evaluate=evaluate_pur_insider_risk_readiness,
            input_models=("purview_insider_risk",),
            collector_id="graph_purview_insider_risk",
            evaluation_mode=EvaluationMode.DIRECT,
            backend=Backend.GRAPH,
        )
    finally:
        catalog.exit_module("licenselens.evaluators.bindings.purview")

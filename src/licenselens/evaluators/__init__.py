"""Evaluator package surface backed by the typed assessment registry."""

from __future__ import annotations

from licenselens.evaluators.common import Evaluation, Evaluator


def evaluator_for_check(check_id: str) -> Evaluator:
    from licenselens.engine.registry import default_registry

    return default_registry().evaluator_callable(check_id)


def evidence_keys_for_check(check_id: str) -> tuple[str, ...]:
    from licenselens.engine.registry import default_registry

    return default_registry().evaluator_for(check_id).input_models


__all__ = [
    "Evaluation",
    "Evaluator",
    "evaluator_for_check",
    "evidence_keys_for_check",
]

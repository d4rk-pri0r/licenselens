"""Risk-based Conditional Access evaluators (high user / sign-in risk)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors import conditional_access as ca
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.identity_ca_lib import (
    break_glass_principal_ids,
    ca_coverage_result,
)
from licenselens.models import CheckDefinition


def _policies(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return list(evidence.get("ca_policies") or [])


def evaluate_ca_high_risk_users(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return ca_coverage_result(
        label="High-risk user block",
        policies=_policies(evidence),
        predicate=ca.blocks_high_user_risk,
        justified=break_glass_principal_ids(evidence),
        ok_summary="Enforced Conditional Access blocks users marked high risk.",
        ok_customer=(
            "Accounts Microsoft marks as high risk are blocked until an admin cleans them up."
        ),
        gap_summary="No enforced Conditional Access policy blocks high-risk users.",
        gap_customer=("Compromised accounts marked high risk may still sign in successfully."),
    )


def evaluate_ca_high_risk_signins(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    return ca_coverage_result(
        label="High-risk sign-in block",
        policies=_policies(evidence),
        predicate=ca.blocks_high_sign_in_risk,
        justified=break_glass_principal_ids(evidence),
        ok_summary="Enforced Conditional Access blocks high-risk sign-ins.",
        ok_customer="Suspicious sign-ins marked high risk are blocked automatically.",
        gap_summary="No enforced Conditional Access policy blocks high-risk sign-ins.",
        gap_customer="Suspicious high-risk sign-ins may still succeed.",
    )

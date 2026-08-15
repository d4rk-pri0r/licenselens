"""DKIM signing evaluator."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.exchange_models import PolicyItem
from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.exchange_lib import (
    direct_meta,
    exchange_bundle,
    items,
    prop_bool,
    usable,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_exo_dkim_enabled(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    bundle = exchange_bundle(evidence)
    if not usable(bundle, "exo_dkim", "dkim"):
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="DKIM signing configuration could not be read; treated as unresolved.",
            evidence={"surface": "dkim", "adapter": "exo_dkim", "readable": False},
            customer_summary="We could not confirm whether DKIM signing is turned on.",
            confidence=Confidence.MEDIUM,
            limitations=["DKIM surface was not readable via Exchange Online PowerShell."],
        )
    configs: list[PolicyItem] = items(bundle, "exo_dkim", "dkim")
    if not configs:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary="No DKIM signing configurations were returned.",
            evidence={"dkim_configs": 0},
            customer_summary="We found no DKIM records; verify DKIM signing per domain.",
            confidence=Confidence.MEDIUM,
            limitations=["Empty DKIM inventory; cannot confirm all domains are signed."],
        )
    disabled = [item.name for item in configs if prop_bool(item, "Enabled") is False]
    evidence_out = {"dkim_configs": len(configs), "disabled_domains": disabled}
    if disabled:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"DKIM signing is disabled for {len(disabled)} domain(s): {', '.join(disabled)}."
            ),
            evidence=evidence_out,
            customer_summary="Not all of your domains are DKIM-signed. Enable it for each.",
            **direct_meta(),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="DKIM signing is enabled for all returned domains.",
        evidence=evidence_out,
        customer_summary="Your domains sign outgoing mail with DKIM.",
        **direct_meta(),
    )

"""Purview workload evaluators."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, Confidence, FindingStatus


def evaluate_purview_dlp(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess DLP enforcement using Secure Score proxy (and optional Graph)."""
    del check
    bundle = dict(evidence.get("purview_dlp") or {})
    score = dict(bundle.get("dlp_secure_score") or {})
    matched = int(score.get("matched_count") or 0)
    ratio = score.get("ratio")
    weak = int(score.get("weak_control_count") or 0)
    evidence_out = {
        **bundle,
        "proxy": True,
        "note": (
            "Uses Microsoft Secure Score DLP/information-protection controls as a "
            "proxy when direct Purview policy APIs are unavailable to the app."
        ),
    }
    proxy_meta = dict(
        confidence=Confidence.LOW,
        data_sources=["secureScore.controlScores (proxy)"],
        limitations=["Secure Score proxy — verify DLP enforce mode in Purview portal."],
    )

    if matched == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No DLP-related Secure Score controls were found; cannot confirm "
                "Purview DLP enforcement automatically."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not automatically confirm data-leak guardrails. Ask IT "
                "whether DLP policies are enforced for email and files."
            ),
            **proxy_meta,
        )

    r = float(ratio) if ratio is not None else 0.0
    # Never emit OK for proxy DLP (strict policy)
    if r >= 0.85 and weak == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Secure Score DLP-related controls look strong "
                f"({matched} controls, ~{r * 100:.0f}%) — provisional until portal verify."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Score signals suggest data-leak guardrails are largely on — confirm "
                "enforce mode in the Purview portal."
            ),
            **proxy_meta,
        )

    if r >= 0.4:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Secure Score suggests partial DLP posture "
                f"({matched} controls, ~{r * 100:.0f}%; weak={weak})."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some data-protection rules may exist, but enforcement still looks "
                "incomplete or stuck in testing. Verify in the portal."
            ),
            **proxy_meta,
        )

    return Evaluation(
        status=FindingStatus.GAP,
        summary=(
            f"Secure Score suggests DLP is largely unused "
            f"({matched} controls, ~{r * 100:.0f}% completion)."
        ),
        evidence=evidence_out,
        customer_summary=(
            "You appear to pay for data-leak protection that is not meaningfully "
            "enforced yet. Confirm in the Purview portal."
        ),
        **proxy_meta,
    )

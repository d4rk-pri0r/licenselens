"""Defender workload evaluators (MDI + re-export MDO)."""

from __future__ import annotations

from typing import Any

from licenselens.evaluators.common import Evaluation, score_status
from licenselens.evaluators.defender_mdo import evaluate_mdo_p2_policies
from licenselens.models import CheckDefinition, Confidence, FindingStatus

__all__ = [
    "evaluate_mdi_sensors",
    "evaluate_mdo_p2_policies",
]


def evaluate_mdi_sensors(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Assess Defender for Identity posture via Secure Score control signals."""
    del check
    from licenselens.collectors.secure_score import MDI_CONTROL_HINTS, summarize_controls

    controls = list(evidence.get("secure_score_controls") or [])
    summary = summarize_controls(controls, MDI_CONTROL_HINTS)
    ratio = summary.get("ratio")
    matched = int(summary.get("matched_count") or 0)
    evidence_out = {
        "source": "secureScore.controlScores",
        "proxy": True,
        "matched_controls": matched,
        "score_ratio": ratio,
        "controls": summary.get("controls") or [],
        "note": (
            "Defender for Identity sensor health is approximated from Secure Score "
            "controls when the MDI API is not configured."
        ),
    }
    proxy_meta = dict(
        confidence=Confidence.LOW,
        data_sources=["secureScore.controlScores (proxy)"],
        limitations=["Secure Score proxy — verify MDI sensors in the Defender portal."],
    )

    if matched == 0:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                "No Defender for Identity–related Secure Score controls were found. "
                "Cannot confirm sensor deployment from this signal alone."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not confirm whether on-site directory attack sensors are "
                "installed. If you still run office domain controllers, ask IT to verify."
            ),
            **proxy_meta,
        )

    status = score_status(float(ratio) if ratio is not None else None, matched=matched)
    if status == FindingStatus.OK:
        status = FindingStatus.PARTIAL
    pct = f"{float(ratio) * 100:.0f}%" if ratio is not None else "n/a"
    if ratio is not None and float(ratio) >= 0.85:
        cust = (
            "Score signals suggest on-site directory protection is largely healthy — "
            "confirm sensors in the Defender portal."
        )
    elif status == FindingStatus.PARTIAL:
        cust = (
            "Some Defender for Identity protections appear configured, but "
            "coverage may be incomplete. Verify sensors in the portal."
        )
    else:
        cust = (
            "You may be paying for directory attack sensors that are missing or "
            "unhealthy. Verify in the portal."
        )
    return Evaluation(
        status=status,
        summary=(
            f"Defender for Identity–related Secure Score completion ~{pct} "
            f"across {matched} control(s) (proxy — not a direct sensor inventory)."
        ),
        evidence=evidence_out,
        customer_summary=cust,
        **proxy_meta,
    )

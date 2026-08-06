"""Purview DLP posture signals (Secure Score proxy + optional Graph)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.secure_score import (
    control_matches,
    summarize_controls,
)
from licenselens.graph import GraphClient

DLP_CONTROL_HINTS: tuple[str, ...] = (
    "data loss prevention",
    "dlp",
    "information protection",
    "sensitivity label",
    "auto-label",
    "auto label",
    "protect your sensitive",
    "endpoint dlp",
)


def summarize_dlp_from_secure_score(controls: list[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize_controls(controls, DLP_CONTROL_HINTS)
    matched = [c for c in controls if control_matches(c, DLP_CONTROL_HINTS)]
    # Heuristic: low individual scores suggest not enforced
    zeroish = 0
    for c in matched:
        sc = float(c.get("score") or 0)
        mx = float(c.get("maxScore") or (1.0 if sc <= 1 else sc) or 1)
        if mx > 0 and (sc / mx) < 0.25:
            zeroish += 1
    summary["weak_control_count"] = zeroish
    summary["source"] = "secureScore.controlScores"
    return summary


def try_collect_graph_dlp_policies(client: GraphClient) -> list[dict[str, Any]] | None:
    """Best-effort Graph DLP policy list (may 404/403 on many tenants)."""
    candidates = [
        "/security/dataSecurityAndGovernance/protectionScopes",  # unlikely
        "/beta/security/informationProtection/policy",
    ]
    # Stay on v1 client base; try known beta path via absolute URL if needed
    try:
        # Graph security dataGovernance is evolving; attempt a safe known list
        data = client.get(
            "https://graph.microsoft.com/beta/security/informationProtection/labelPolicySettings"
        )
        if isinstance(data, dict):
            return [data]
    except Exception:
        pass
    del candidates
    return None


def collect_purview_dlp_bundle(
    client: GraphClient | None,
    secure_score_controls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build DLP evidence preferring Secure Score, optional Graph enrichment."""
    score_summary = summarize_dlp_from_secure_score(secure_score_controls)
    graph_policies = None
    graph_error = None
    if client is not None:
        try:
            graph_policies = try_collect_graph_dlp_policies(client)
        except Exception as exc:  # noqa: BLE001
            graph_error = str(exc)

    return {
        "dlp_secure_score": score_summary,
        "dlp_graph_policies": graph_policies,
        "dlp_graph_error": graph_error,
        "proxy": True,
    }


# Dry-run: weak DLP score → gap
DEMO_DLP_BUNDLE: dict[str, Any] = {
    "dlp_secure_score": {
        "matched_count": 2,
        "score_sum": 0.2,
        "max_sum": 2.0,
        "ratio": 0.1,
        "weak_control_count": 2,
        "source": "secureScore.controlScores",
        "controls": [
            {
                "controlName": "DLP_Policies_Enabled",
                "description": "Data loss prevention policies",
                "score": 0.1,
                "maxScore": 1.0,
            },
            {
                "controlName": "Endpoint_DLP",
                "description": "Endpoint DLP",
                "score": 0.1,
                "maxScore": 1.0,
            },
        ],
    },
    "dlp_graph_policies": None,
    "dlp_graph_error": None,
    "proxy": True,
}

# Ensure demo secure score includes DLP-ish controls when merged
DEMO_SECURE_SCORE_DLP_CONTROLS: list[dict[str, Any]] = [
    {
        "controlName": "DLP_Policies_Enabled",
        "description": "Data loss prevention policies not enforced",
        "score": 0.1,
        "maxScore": 1.0,
    },
    {
        "controlName": "Information_Protection_DLP",
        "description": "Information protection and DLP",
        "score": 0.15,
        "maxScore": 1.0,
    },
]

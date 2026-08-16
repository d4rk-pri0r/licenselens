"""Purview DLP/eDiscovery/insider-risk posture signals (direct Graph + Secure Score fallback)."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.secure_score import (
    control_matches,
    summarize_controls,
)
from licenselens.errors import GraphError
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

# Graph v1.0 endpoints for Purview policy evidence.
DLP_POLICIES_PATH = "/security/dataLossPreventionPolicies"
DLP_APPS_PATH = "/security/dataLossPreventionApps"
EDISCOVERY_CASES_PATH = "/security/cases/ediscoveryCases"
# Insider Risk Management policies are only exposed on the beta endpoint.
INSIDER_RISK_POLICIES_PATH = "/security/insiderRiskManagement/policies"

# DLP policy mode values that count as enforced in production.
_ENFORCEMENT_MODES: frozenset[str] = frozenset({"production", "enforce", "enforced", "active"})


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


def _policy_mode(policy: dict[str, Any]) -> str:
    raw = policy.get("mode")
    return str(raw).strip().lower() if raw is not None else ""


def _is_enforced(policy: dict[str, Any]) -> bool:
    return _policy_mode(policy) in _ENFORCEMENT_MODES


def summarize_dlp_policies(
    policies: list[dict[str, Any]],
    apps: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Summarize direct Graph DLP policy/app evidence into evaluator-facing fields."""
    enforced = [p for p in policies if _is_enforced(p)]
    names = [
        str(p.get("name") or p.get("displayName") or "").strip()
        for p in policies
        if str(p.get("name") or p.get("displayName") or "").strip()
    ]
    app_summary: dict[str, Any] | None = None
    if apps is not None:
        app_summary = {
            "count": len(apps),
            "states": sorted({str(a.get("state") or "unknown") for a in apps}),
        }
    return {
        "policy_count": len(policies),
        "enforced_count": len(enforced),
        "test_or_other_count": len(policies) - len(enforced),
        "policy_names": names,
        "apps": app_summary,
        "source": "graph.security.dataLossPrevention",
        "direct": True,
    }


def try_collect_graph_dlp(
    client: GraphClient,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]] | None]:
    """Read DLP policies (and apps when available) via Graph v1.0.

    Raises GraphError when neither endpoint is readable so the caller can fall
    back to the Secure Score proxy.
    """
    policies = client.get_list(DLP_POLICIES_PATH)
    try:
        apps = client.get_list(DLP_APPS_PATH)
    except GraphError:
        apps = None
    return policies, apps


def collect_purview_dlp_bundle(
    client: GraphClient | None,
    secure_score_controls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build DLP evidence preferring direct Graph policies, Secure Score as fallback."""
    score_summary = (
        summarize_dlp_from_secure_score(secure_score_controls) if secure_score_controls else None
    )
    direct_summary: dict[str, Any] | None = None
    graph_error: str | None = None
    if client is not None:
        try:
            policies, apps = try_collect_graph_dlp(client)
            direct_summary = summarize_dlp_policies(policies, apps)
        except GraphError as exc:
            graph_error = str(exc)

    proxy = direct_summary is None
    return {
        "dlp_secure_score": score_summary,
        "dlp_graph": direct_summary,
        "dlp_graph_error": graph_error,
        "proxy": proxy,
        "source": (
            "graph.security.dataLossPreventionPolicies"
            if direct_summary is not None
            else "secureScore.controlScores (proxy)"
        ),
    }


def collect_purview_ediscovery_bundle(client: GraphClient) -> dict[str, Any]:
    """Read Premium eDiscovery cases via Graph v1.0 (GA)."""
    cases = client.get_list(EDISCOVERY_CASES_PATH)
    names = [
        str(c.get("displayName") or "").strip()
        for c in cases
        if str(c.get("displayName") or "").strip()
    ]
    return {
        "case_count": len(cases),
        "case_names": names,
        "source": "graph.security.cases.ediscoveryCases",
        "direct": True,
        "proxy": False,
    }


def collect_purview_insider_risk_bundle(client: GraphClient) -> dict[str, Any]:
    """Read Insider Risk Management policies via the Graph beta endpoint."""
    policies = client.get_list(INSIDER_RISK_POLICIES_PATH)
    names = [
        str(p.get("name") or p.get("displayName") or "").strip()
        for p in policies
        if str(p.get("name") or p.get("displayName") or "").strip()
    ]
    return {
        "policy_count": len(policies),
        "policy_names": names,
        "source": "graph.beta.security.insiderRiskManagement.policies",
        "direct": True,
        "proxy": False,
    }


# Dry-run fixtures.
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
    "dlp_graph": None,
    "dlp_graph_error": "demo: direct Graph DLP read unavailable",
    "proxy": True,
    "source": "secureScore.controlScores (proxy)",
}

DEMO_DLP_GRAPH_BUNDLE: dict[str, Any] = {
    "dlp_secure_score": None,
    "dlp_graph": {
        "policy_count": 1,
        "enforced_count": 1,
        "test_or_other_count": 0,
        "policy_names": ["Contoso data leak protection"],
        "apps": {"count": 3, "states": ["enabled"]},
        "source": "graph.security.dataLossPrevention",
        "direct": True,
    },
    "dlp_graph_error": None,
    "proxy": False,
    "source": "graph.security.dataLossPreventionPolicies",
}

DEMO_EDISCOVERY_BUNDLE: dict[str, Any] = {
    "case_count": 1,
    "case_names": ["Contoso investigation 2026-Q1"],
    "source": "graph.security.cases.ediscoveryCases",
    "direct": True,
    "proxy": False,
}

DEMO_INSIDER_RISK_BUNDLE: dict[str, Any] = {
    "policy_count": 1,
    "policy_names": ["Contoso data leak by departing users"],
    "source": "graph.beta.security.insiderRiskManagement.policies",
    "direct": True,
    "proxy": False,
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

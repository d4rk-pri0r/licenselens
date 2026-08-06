"""Collect Microsoft Secure Score snapshots (Graph security API)."""

from __future__ import annotations

from typing import Any

from licenselens.graph import GraphClient

# Control name / title fragments used to map Secure Score → product outcomes.
MDO_CONTROL_HINTS: tuple[str, ...] = (
    "safe links",
    "safe attachments",
    "atp",
    "defender for office",
    "office 365 advanced threat",
    "anti-phishing",
    " spoof ",
    "mailbox intelligence",
    "impersonation",
    "calendar sharing",  # weak - avoid
    "common attachment types filter",
    "zap",
    "zero-hour",
)

MDE_CONTROL_HINTS: tuple[str, ...] = (
    "defender for endpoint",
    "endpoint protection",
    "microsoft defender antivirus",
    "device security",
    "edr",
    "attack surface reduction",
    "controlled folder",
)

MDI_CONTROL_HINTS: tuple[str, ...] = (
    "defender for identity",
    "azure advanced threat protection",
    "azure atp",
    "identity secure score",
    "domain controllers",
)


def collect_latest_secure_score(client: GraphClient) -> dict[str, Any] | None:
    """GET /security/secureScores?$top=1 (most recent)."""
    # Prefer ordered query; fall back to first page
    try:
        data = client.get(
            "/security/secureScores",
            params={"$top": "1", "$orderby": "createdDateTime desc"},
        )
    except Exception:
        data = client.get("/security/secureScores", params={"$top": "1"})
    rows = data.get("value") or []
    if not rows:
        return None
    return rows[0] if isinstance(rows[0], dict) else None


def collect_secure_score_control_profiles(client: GraphClient) -> list[dict[str, Any]]:
    """GET /security/secureScoreControlProfiles (control metadata)."""
    return client.get_list("/security/secureScoreControlProfiles", max_pages=20)


def _norm(text: str) -> str:
    # Treat underscores/hyphens as spaces so SafeLinks_Enabled matches "safe links"
    cleaned = text.lower().replace("_", " ").replace("-", " ")
    return " ".join(cleaned.split())


def control_matches(control: dict[str, Any], hints: tuple[str, ...]) -> bool:
    blob = " ".join(
        str(control.get(k) or "")
        for k in ("controlName", "title", "controlCategory", "service", "description")
    )
    n = _norm(blob)
    return any(_norm(h) in n for h in hints)


def extract_control_scores(score_doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not score_doc:
        return []
    controls = score_doc.get("controlScores") or []
    return [c for c in controls if isinstance(c, dict)]


def summarize_controls(
    controls: list[dict[str, Any]],
    hints: tuple[str, ...],
) -> dict[str, Any]:
    matched = [c for c in controls if control_matches(c, hints)]
    if not matched:
        return {
            "matched_count": 0,
            "score_sum": 0.0,
            "max_sum": 0.0,
            "ratio": None,
            "controls": [],
        }

    score_sum = 0.0
    max_sum = 0.0
    details: list[dict[str, Any]] = []
    for c in matched:
        sc = float(c.get("score") or 0)
        # maxScore may be absent; treat missing as 1 if score in 0..1 else score
        mx = c.get("maxScore")
        if mx is None:
            mx = 1.0 if sc <= 1.0 else sc
        mx_f = float(mx) if float(mx) > 0 else 1.0
        score_sum += sc
        max_sum += mx_f
        details.append(
            {
                "controlName": c.get("controlName") or c.get("controlName"),
                "description": (c.get("description") or "")[:160],
                "score": sc,
                "maxScore": mx_f,
            }
        )

    ratio = (score_sum / max_sum) if max_sum else None
    return {
        "matched_count": len(matched),
        "score_sum": score_sum,
        "max_sum": max_sum,
        "ratio": ratio,
        "controls": details[:15],
    }


# Dry-run demo Secure Score controlScores (partial MDO, weak MDE, no MDI)
DEMO_SECURE_SCORE: dict[str, Any] = {
    "id": "demo-score",
    "azureTenantId": "00000000-0000-0000-0000-000000000000",
    "createdDateTime": "2026-08-01T00:00:00Z",
    "currentScore": 42.0,
    "maxScore": 100.0,
    "controlScores": [
        {
            "controlName": "SafeLinks_Enabled",
            "description": "Safe Links is enabled for email",
            "score": 1.0,
            "maxScore": 1.0,
        },
        {
            "controlName": "SafeAttachments_Enabled",
            "description": "Safe Attachments not fully rolled out",
            "score": 0.0,
            "maxScore": 1.0,
        },
        {
            "controlName": "AntiPhish_Policy",
            "description": "Anti-phishing policy in audit mode",
            "score": 0.35,
            "maxScore": 1.0,
        },
        {
            "controlName": "DefenderForEndpoint_Onboard",
            "description": "Devices onboarded to Defender for Endpoint",
            "score": 0.4,
            "maxScore": 1.0,
        },
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
    ],
}

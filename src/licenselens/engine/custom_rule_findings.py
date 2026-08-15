from __future__ import annotations

from html import unescape
from typing import Final
from urllib.parse import urlparse

from licenselens.config_models import CustomRule
from licenselens.models import (
    CheckPack,
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    ValueImpact,
    Workload,
)
from licenselens.schema_contracts import JsonValue

_CUSTOM_SOURCE: Final = "custom_rule"
_SAFE_TEXT_CHARS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:;_-/()[]"
)


def matched_custom_finding(rule: CustomRule, profile_id: str, profile_ids: list[str]) -> Finding:
    rule_id = safe_custom_rule_id(str(rule.id))
    safe_profile_id = safe_custom_rule_id(profile_id)
    safe_profile_ids = [safe_custom_rule_id(item) for item in profile_ids]
    title = safe_custom_rule_text(rule.title or rule_id)
    summary = safe_custom_rule_text(
        rule.description or rule.rationale or f"Custom rule {rule_id} matched."
    )
    return Finding(
        check_id=f"custom:{safe_profile_id}:{rule_id}",
        title=title,
        workload=Workload.GENERAL,
        status=FindingStatus.GAP,
        severity=Severity.INFO,
        value_impact=ValueImpact.LOW,
        summary=summary,
        customer_title=title,
        customer_summary=summary,
        remediation=safe_custom_rule_text(rule.rationale),
        deep_link=safe_custom_rule_link(rule.references),
        references=[url for url in rule.references if safe_custom_rule_link([url]) is not None],
        data_sources=[_CUSTOM_SOURCE],
        confidence=Confidence.MEDIUM,
        evidence=custom_rule_provenance(rule_id, safe_profile_id, safe_profile_ids, "matched"),
        pack=CheckPack.STARTER,
    )


def errored_custom_finding(
    profile_id: str,
    rule_id: str,
    diagnostic: str,
    profile_ids: list[str],
) -> Finding:
    safe_rule_id = safe_custom_rule_id(rule_id)
    safe_profile_id = safe_custom_rule_id(profile_id)
    safe_profile_ids = [safe_custom_rule_id(item) for item in profile_ids]
    return Finding(
        check_id=f"custom:{safe_profile_id}:{safe_rule_id}",
        title=f"Custom rule {safe_rule_id} could not be evaluated",
        workload=Workload.GENERAL,
        status=FindingStatus.ERROR,
        severity=Severity.INFO,
        value_impact=ValueImpact.LOW,
        summary=safe_custom_rule_text(diagnostic),
        data_sources=[_CUSTOM_SOURCE],
        confidence=Confidence.LOW,
        evidence=custom_rule_provenance(safe_rule_id, safe_profile_id, safe_profile_ids, "error"),
        pack=CheckPack.STARTER,
    )


def custom_rule_provenance(
    rule_id: str,
    profile_id: str,
    profile_ids: list[str],
    outcome: str,
) -> dict[str, JsonValue]:
    return {
        "source": _CUSTOM_SOURCE,
        "custom_rule_id": rule_id,
        "profile_id": profile_id,
        "profile_ids": list(profile_ids),
        "outcome": outcome,
    }


def safe_custom_rule_id(value: str) -> str:
    cleaned = "".join(char for char in unescape(value) if char.isalnum() or char in "-_")[:96]
    return cleaned or "rule"


def safe_custom_rule_text(value: str) -> str:
    return "".join(char for char in unescape(value) if char in _SAFE_TEXT_CHARS).strip()[:512]


def safe_custom_rule_link(urls: list[str]) -> str | None:
    for url in urls:
        parsed = urlparse(url)
        credentials_absent = parsed.username is None and parsed.password is None
        if parsed.scheme == "https" and parsed.netloc and credentials_absent:
            return url
    return None

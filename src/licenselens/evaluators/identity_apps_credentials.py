"""Application credential lifetime and ownership evaluators."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus

_PASSWORD_MAX_DAYS: Final = 180
_CERT_MAX_DAYS: Final = 365
_STALE_DAYS: Final = 365


def _apps(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    bundle = evidence.get("applications_bundle") or {}
    if isinstance(bundle, dict) and bundle.get("applications") is not None:
        return list(bundle.get("applications") or [])
    return list(evidence.get("applications") or [])


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _scan_now(evidence: dict[str, Any]) -> datetime:
    raw = evidence.get("scanned_at")
    if raw is not None:
        parsed = _parse_dt(raw)
        if parsed is not None:
            return parsed
    return datetime.now(UTC)


def _credential_lifetime_issues(
    apps: list[dict[str, Any]],
    *,
    now: datetime,
    field: str,
    max_days: int,
) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    for app in apps:
        creds = list(app.get(field) or [])
        for cred in creds:
            end = _parse_dt(cred.get("endDateTime"))
            start = _parse_dt(cred.get("startDateTime"))
            if end is None:
                continue
            lifetime_days = (end - (start or now)).days if start else (end - now).days
            if lifetime_days > max_days:
                issues.append(
                    {
                        "app": str(app.get("displayName") or app.get("id") or "?"),
                        "end": end.date().isoformat(),
                        "lifetime_days": str(lifetime_days),
                    }
                )
    return issues[:20]


def evaluate_app_password_lifetime(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    issues = _credential_lifetime_issues(
        _apps(evidence),
        now=_scan_now(evidence),
        field="passwordCredentials",
        max_days=_PASSWORD_MAX_DAYS,
    )
    evidence_out = {"long_lived_password_count": len(issues), "sample": issues}
    if issues:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Found {len(issues)} app password credential(s) lasting longer than "
                f"{_PASSWORD_MAX_DAYS} days."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Some app secrets stay valid for a very long time, increasing breach impact."
            ),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"No app password credentials exceed {_PASSWORD_MAX_DAYS} days.",
        evidence=evidence_out,
        customer_summary="App secrets we could see stay within a reasonable lifetime.",
    )


def evaluate_app_certificate_lifetime(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    issues = _credential_lifetime_issues(
        _apps(evidence),
        now=_scan_now(evidence),
        field="keyCredentials",
        max_days=_CERT_MAX_DAYS,
    )
    evidence_out = {"long_lived_certificate_count": len(issues), "sample": issues}
    if issues:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                f"Found {len(issues)} app certificate(s) lasting longer than {_CERT_MAX_DAYS} days."
            ),
            evidence=evidence_out,
            customer_summary=("Some app certificates stay valid longer than a year."),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary=f"No app certificates exceed {_CERT_MAX_DAYS} days.",
        evidence=evidence_out,
        customer_summary="App certificates we could see stay within a reasonable lifetime.",
    )


def evaluate_app_ownerless_or_stale(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    apps = _apps(evidence)
    owners_map = evidence.get("application_owners") or {}
    if not isinstance(owners_map, dict):
        owners_map = {}
    now = _scan_now(evidence)
    ownerless: list[str] = []
    stale: list[str] = []
    for app in apps:
        app_id = str(app.get("id") or "")
        name = str(app.get("displayName") or app_id or "?")
        owners = owners_map.get(app_id)
        if owners is not None and len(list(owners)) == 0:
            ownerless.append(name)
        created = _parse_dt(app.get("createdDateTime"))
        creds = list(app.get("passwordCredentials") or []) + list(app.get("keyCredentials") or [])
        latest_end = None
        for cred in creds:
            end = _parse_dt(cred.get("endDateTime"))
            if end and (latest_end is None or end > latest_end):
                latest_end = end
        if created and (now - created).days > _STALE_DAYS and not creds:
            stale.append(name)
        elif latest_end and latest_end < now and (now - latest_end).days > 30:
            stale.append(name)
    evidence_out = {
        "app_count": len(apps),
        "ownerless_count": len(ownerless),
        "stale_count": len(stale),
        "ownerless_sample": ownerless[:10],
        "stale_sample": stale[:10],
    }
    if ownerless or stale:
        status = FindingStatus.GAP if len(ownerless) + len(stale) >= 2 else FindingStatus.PARTIAL
        return Evaluation(
            status=status,
            summary=(f"Found {len(ownerless)} ownerless and {len(stale)} stale application(s)."),
            evidence=evidence_out,
            customer_summary=(
                "Some apps have no owner or look abandoned, which makes secret and "
                "permission cleanup harder."
            ),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="No ownerless or clearly stale applications were detected in the sample.",
        evidence=evidence_out,
        customer_summary="App registrations we reviewed look owned and active.",
    )


def evaluate_app_expiring_credentials(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    apps = _apps(evidence)
    now = _scan_now(evidence)
    expiring: list[dict[str, str]] = []
    expired: list[dict[str, str]] = []
    for app in apps:
        name = str(app.get("displayName") or app.get("id") or "?")
        for field in ("passwordCredentials", "keyCredentials"):
            for cred in list(app.get(field) or []):
                end = _parse_dt(cred.get("endDateTime"))
                if end is None:
                    continue
                days = (end - now).days
                row = {"app": name, "end": end.date().isoformat(), "days": str(days)}
                if days < 0:
                    expired.append(row)
                elif days <= 30:
                    expiring.append(row)
    evidence_out = {
        "expiring_within_30_days": expiring[:15],
        "already_expired": expired[:15],
        "expiring_count": len(expiring),
        "expired_count": len(expired),
    }
    if expiring or expired:
        return Evaluation(
            status=FindingStatus.PARTIAL if not expired else FindingStatus.GAP,
            summary=(
                f"Found {len(expiring)} credential(s) expiring within 30 days and "
                f"{len(expired)} already expired."
            ),
            evidence=evidence_out,
            customer_summary=("Some app secrets or certificates are expired or about to expire."),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="No app credentials are expired or expiring within 30 days.",
        evidence=evidence_out,
        customer_summary="App secrets and certificates look current.",
    )

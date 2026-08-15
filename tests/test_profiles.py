from __future__ import annotations

import pytest
from pydantic import ValidationError

from licenselens.auth import AuthMode, build_auth_context
from licenselens.config_models import AssessmentProfile
from licenselens.engine.loader import load_checks
from licenselens.engine.profiles import (
    ProfileReferenceError,
    ProfileScalarOverrides,
    apply_profile_to_findings,
    compose_profile,
    load_builtin_profiles,
    resolve_profile_checks,
)
from licenselens.engine.runner import run_scan
from licenselens.models import DEFAULT_PACKS, FindingStatus


def _profile(raw: dict[str, object]) -> AssessmentProfile:
    return AssessmentProfile.model_validate({"schema_version": "1.0", "name": "Org"} | raw)


def test_builtin_profiles_load_deterministically_and_resolve_expected_checks() -> None:
    # Given: the shipped profile and check catalogs.
    checks = load_checks()

    # When: built-ins are loaded and resolved twice.
    first = load_builtin_profiles()
    second = load_builtin_profiles()
    resolved = {str(profile.id): resolve_profile_checks(profile, checks) for profile in first}
    resolved_again = {
        str(profile.id): resolve_profile_checks(profile, checks) for profile in second
    }

    # Then: ordering and profile-to-check selection are deterministic.
    assert [profile.id for profile in first] == sorted(resolved)
    assert [profile.model_dump(mode="json") for profile in first] == [
        profile.model_dump(mode="json") for profile in second
    ]
    assert resolved == resolved_again
    assert resolved["email"] == [
        "exo-dkim-enabled",
        "exo-dmarc-agency-contact",
        "exo-dmarc-federal-contact",
        "exo-dmarc-published",
        "exo-dmarc-reject",
        "exo-external-sender-warnings",
        "exo-forwarding-external-disabled",
        "exo-mailbox-audit-enabled",
        "exo-sharing-calendar-not-all-domains",
        "exo-sharing-contact-not-all-domains",
        "exo-smtp-auth-disabled",
        "exo-spf-published",
        "mdo-alert-policies-enabled",
        "mdo-anti-spam-no-allowed-domains",
        "mdo-audit-retention",
        "mdo-connection-filter-no-ip-allow",
        "mdo-connection-filter-no-safe-list",
        "mdo-impersonation-domains-owned",
        "mdo-impersonation-partner-domains",
        "mdo-impersonation-users-protected",
        "mdo-malware-file-filter",
        "mdo-malware-zap",
        "mdo-p2-policies-default",
        "mdo-safe-attachments-block",
        "mdo-safe-attachments-spo-teams",
        "mdo-safe-links-block-list",
        "mdo-safe-links-click-tracking",
        "mdo-safe-links-real-time-scan",
        "mdo-safety-tips-enabled",
        "mdo-spam-phish-not-inbox",
        "mdo-unified-audit-enabled",
        "pur-dlp-enforcement-block",
        "pur-dlp-locations-complete",
        "pur-dlp-notifications",
        "pur-dlp-policy-present",
    ]
    assert resolved["endpoint"] == [
        "endpoint-compliance-noncompliance-action",
        "endpoint-compliance-policy-assigned",
        "endpoint-enrollment-coverage",
        "endpoint-mde-connector",
        "endpoint-security-baseline",
        "endpoint-security-policy-coverage",
        "mde-onboard-gap",
        "mde-sensor-health",
        "mdi-sensors-missing",
        "xdr-incident-readiness",
    ]
    assert "id-ca-legacy-auth-block" in resolved["identity"]
    assert "id-ca-priv-gaps" in resolved["identity"]
    assert len(resolved["identity"]) >= 40
    assert "id-ca-legacy-auth-block" in resolved["core"]
    assert "mde-onboard-gap" in resolved["core"]


def test_core_profile_preserves_current_default_pack_behavior() -> None:
    # Given: no CLI wiring has selected a profile yet.
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")

    # When: default scan behavior and the core profile contract are inspected.
    result = run_scan(auth, dry_run=True)
    core = compose_profile("core")

    # Then: current scan scope is unchanged and core carries the existing default packs.
    assert result.profile_ids == []
    assert len(result.findings) == len([check for check in load_checks() if check.enabled])
    assert core.profile.packs == DEFAULT_PACKS
    assert result.packs_scanned == DEFAULT_PACKS


def test_organization_profile_and_cli_scalar_overrides_win_by_precedence() -> None:
    # Given: an organization profile changes profile scalars and lists.
    org = _profile(
        {
            "id": "org-core",
            "packs": ["email"],
            "backend_preferences": {
                "preferred": ["exchange_online"],
                "allow_proxy": False,
                "allow_manual": False,
            },
        }
    )

    # When: it is composed above core with a CLI scalar override.
    resolved = compose_profile(
        "core",
        organization_profile=org,
        cli_overrides=ProfileScalarOverrides(allow_proxy=True),
    )

    # Then: organization lists replace built-in lists and CLI scalar wins last.
    assert resolved.profile.packs == ["email"]
    assert [backend.value for backend in resolved.profile.backend_preferences.preferred] == [
        "exchange_online"
    ]
    assert resolved.profile.backend_preferences.allow_proxy is True
    assert resolved.profile.backend_preferences.allow_manual is False
    assert resolved.profile_ids == ["core", "org-core"]


def test_lists_replace_unless_schema_marks_them_mergeable() -> None:
    # Given: built-in full has packs, one exclusion, and one custom rule.
    org = _profile(
        {
            "id": "org-full",
            "packs": ["identity"],
            "custom_rules": [
                {"id": "org-rule", "selector": "finding.status", "operator": "exists"}
            ],
            "accepted_risks": [
                {
                    "id": "org-risk",
                    "check_id": "id-ca-priv-gaps",
                    "owner": "security@example.com",
                    "reason": "Migration accepted.",
                    "expires_on": "2099-12-31",
                }
            ],
        }
    )

    # When: the organization profile is composed over full.
    resolved = compose_profile("full", organization_profile=org)

    # Then: ordinary lists replace, while schema-mergeable lists append deterministically.
    assert resolved.profile.packs == ["identity"]
    assert [rule.id for rule in resolved.profile.custom_rules] == ["full-gap-count", "org-rule"]
    assert [risk.id for risk in resolved.profile.accepted_risks] == ["org-risk"]
    assert [exclusion.id for exclusion in resolved.profile.exclusions] == ["exclude-lab-tenant"]
    assert [
        risk.id
        for risk in compose_profile("scuba", organization_profile=org).profile.accepted_risks
    ] == ["risk-scuba-transition", "org-risk"]


def test_exclusions_require_rationale() -> None:
    # Given: an exclusion with a blank rationale.
    raw = {
        "schema_version": "1.0",
        "id": "bad-exclusion",
        "name": "Bad exclusion",
        "exclusions": [
            {"id": "exclude-1", "check_id": "id-ca-priv-gaps", "reason": "", "owner": "sec"}
        ],
    }

    # When / Then: schema parsing fails before profile composition can hide the issue.
    with pytest.raises(ValidationError) as exc_info:
        AssessmentProfile.model_validate(raw)
    assert "reason" in str(exc_info.value)


def test_waivers_annotate_findings_without_suppression_and_expired_stays_actionable() -> None:
    # Given: a gap finding and both active and expired accepted risks for its check.
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    finding = next(
        f for f in run_scan(auth, dry_run=True).findings if f.check_id == "id-ca-priv-gaps"
    )
    profile = _profile(
        {
            "id": "risk-profile",
            "accepted_risks": [
                {
                    "id": "active-risk",
                    "check_id": finding.check_id,
                    "owner": "security@example.com",
                    "reason": "Rollout accepted.",
                    "expires_on": "2099-12-31",
                },
                {
                    "id": "expired-risk",
                    "check_id": finding.check_id,
                    "owner": "security@example.com",
                    "reason": "Old waiver.",
                    "expires_on": "2000-01-01",
                },
            ],
        }
    )

    # When: waiver application runs over findings.
    annotated = apply_profile_to_findings(
        [finding], compose_profile("core", organization_profile=profile)
    )

    # Then: the finding remains a gap and each waiver is serialized as an annotation.
    assert annotated[0].status is FindingStatus.PARTIAL
    assert [risk.id for risk in annotated[0].accepted_risks] == ["active-risk", "expired-risk"]
    dumped = annotated[0].model_dump(mode="json")
    assert [risk["status"] for risk in dumped["accepted_risks"]] == ["active", "expired"]
    assert dumped["accepted_risks"][0]["suppresses_finding"] is False
    assert dumped["accepted_risks"][1]["suppresses_finding"] is False


def test_invalid_or_missing_profile_references_fail_closed() -> None:
    # Given: unknown profile and unknown check references.
    bad_profile = _profile({"id": "bad", "check_ids": ["missing-check"]})

    # When / Then: each failure is raised before scan scope can silently widen.
    with pytest.raises(ProfileReferenceError) as missing_profile:
        compose_profile("missing-profile")
    assert "unknown profile" in str(missing_profile.value)
    with pytest.raises(ProfileReferenceError) as missing_check:
        resolve_profile_checks(bad_profile, load_checks())
    assert "unknown check" in str(missing_check.value)


def test_profile_effects_are_serialized_on_scan_result() -> None:
    # Given: a composed email profile with proxy enabled by profile config.
    auth = build_auth_context(mode=AuthMode.DRY_RUN, tenant_id="dry-run")
    profile = compose_profile("email")

    # When: the internal runner seam receives the profile.
    result = run_scan(auth, dry_run=True, profile=profile)

    # Then: findings are narrowed, rollup/moves use profile packs, and profile IDs serialize.
    assert result.profile_ids == ["email"]
    assert result.packs_scanned == ["email"]
    assert [finding.check_id for finding in result.findings] == [
        "exo-dmarc-agency-contact",
        "pur-dlp-locations-complete",
        "exo-dmarc-federal-contact",
        "mdo-alert-policies-enabled",
        "mdo-audit-retention",
        "exo-dkim-enabled",
        "exo-dmarc-published",
        "exo-dmarc-reject",
        "exo-external-sender-warnings",
        "exo-forwarding-external-disabled",
        "exo-mailbox-audit-enabled",
        "exo-sharing-calendar-not-all-domains",
        "exo-sharing-contact-not-all-domains",
        "exo-smtp-auth-disabled",
        "exo-spf-published",
        "mdo-anti-spam-no-allowed-domains",
        "mdo-connection-filter-no-ip-allow",
        "mdo-connection-filter-no-safe-list",
        "mdo-impersonation-domains-owned",
        "mdo-impersonation-partner-domains",
        "mdo-impersonation-users-protected",
        "mdo-malware-file-filter",
        "mdo-malware-zap",
        "mdo-p2-policies-default",
        "mdo-safe-attachments-block",
        "mdo-safe-attachments-spo-teams",
        "mdo-safe-links-block-list",
        "mdo-safe-links-click-tracking",
        "mdo-safe-links-real-time-scan",
        "mdo-safety-tips-enabled",
        "mdo-spam-phish-not-inbox",
        "mdo-unified-audit-enabled",
        "pur-dlp-enforcement-block",
        "pur-dlp-notifications",
        "pur-dlp-policy-present",
    ]
    assert result.findings[0].status in {
        FindingStatus.OK,
        FindingStatus.GAP,
        FindingStatus.PARTIAL,
        FindingStatus.SKIPPED,
    }
    assert result.model_dump(mode="json")["profile_ids"] == ["email"]

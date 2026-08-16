"""Wave 3 SharePoint/OneDrive and Teams collaboration evaluator coverage."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.collaboration_demo import demo_collaboration_evidence
from licenselens.engine.loader import load_checks
from licenselens.evaluators.collaboration_sharing import (
    evaluate_spo_domain_restrictions,
    evaluate_spo_onedrive_sharing_limited,
    evaluate_spo_sharing_capability_limited,
    evaluate_spo_unmanaged_device_access,
)
from licenselens.evaluators.collaboration_sharing_links import (
    evaluate_spo_anyone_link_expiration,
    evaluate_spo_anyone_link_view,
    evaluate_spo_default_link_specific,
    evaluate_spo_default_link_view,
    evaluate_spo_verification_reauth,
)
from licenselens.evaluators.collaboration_teams_access import (
    evaluate_teams_email_integration_disabled,
    evaluate_teams_external_access_per_domain,
    evaluate_teams_guest_access_restricted,
    evaluate_teams_unmanaged_inbound_blocked,
    evaluate_teams_unmanaged_outbound_blocked,
)
from licenselens.evaluators.collaboration_teams_apps import (
    evaluate_teams_custom_apps_governed,
    evaluate_teams_microsoft_apps_governed,
    evaluate_teams_third_party_apps_governed,
)
from licenselens.evaluators.collaboration_teams_meeting import (
    evaluate_teams_anonymous_lobby,
    evaluate_teams_anonymous_start_disabled,
    evaluate_teams_broadcast_not_always_record,
    evaluate_teams_dialin_lobby,
    evaluate_teams_external_control_disabled,
    evaluate_teams_internal_auto_admit,
    evaluate_teams_recording_disabled,
)
from licenselens.models import CheckDefinition, Confidence, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.COLLABORATION)


def _demo() -> dict[str, Any]:
    evidence = demo_collaboration_evidence()
    evidence["approved_partner_domains"] = []
    return evidence


def _surface(bundle: dict[str, Any], adapter: str, surface: str) -> dict[str, Any]:
    return bundle["adapters"][adapter]["surfaces"][surface]


def _set_spo_prop(evidence: dict[str, Any], surface: str, prop_name: str, value: object) -> None:
    item = _surface(evidence["collaboration_bundle"], "spo_tenant", surface)["items"][0]
    item["properties"][prop_name] = value


def _set_spo_capability(evidence: dict[str, Any], value: str) -> None:
    _set_spo_prop(evidence, "sharing_capability", "SharingCapability", value)


def test_demo_global_custom_compliant_matrix() -> None:
    evidence = _demo()
    assert (
        evaluate_spo_sharing_capability_limited(
            _check("spo-sharing-capability-limited"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_spo_onedrive_sharing_limited(
            _check("spo-onedrive-sharing-limited"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_spo_domain_restrictions(_check("spo-domain-restrictions"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_spo_default_link_specific(_check("spo-default-link-specific"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_spo_default_link_view(_check("spo-default-link-view"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_spo_verification_reauth(_check("spo-verification-reauth"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_external_control_disabled(
            _check("teams-external-control-disabled"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_anonymous_start_disabled(
            _check("teams-anonymous-start-disabled"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_anonymous_lobby(_check("teams-anonymous-lobby"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_internal_auto_admit(_check("teams-internal-auto-admit"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_dialin_lobby(_check("teams-dialin-lobby"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_external_access_per_domain(
            _check("teams-external-access-per-domain"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_unmanaged_inbound_blocked(
            _check("teams-unmanaged-inbound-blocked"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_unmanaged_outbound_blocked(
            _check("teams-unmanaged-outbound-blocked"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_email_integration_disabled(
            _check("teams-email-integration-disabled"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_spo_unmanaged_device_access(_check("spo-unmanaged-device-access"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_teams_guest_access_restricted(
            _check("teams-guest-access-restricted"), evidence
        ).status
        is FindingStatus.OK
    )
    third_party = evaluate_teams_third_party_apps_governed(
        _check("teams-third-party-apps-governed"), evidence
    )
    assert third_party.status in {FindingStatus.PARTIAL, FindingStatus.SKIPPED}
    assert third_party.status is not FindingStatus.OK
    assert third_party.confidence is not Confidence.HIGH
    custom_apps = evaluate_teams_custom_apps_governed(
        _check("teams-custom-apps-governed"), evidence
    )
    assert custom_apps.status in {FindingStatus.PARTIAL, FindingStatus.SKIPPED}
    assert custom_apps.status is not FindingStatus.OK
    assert custom_apps.confidence is not Confidence.HIGH


def test_weak_custom_recording_policy_not_hidden_by_compliant_global() -> None:
    evidence = _demo()
    result = evaluate_teams_recording_disabled(_check("teams-recording-disabled"), evidence)
    assert result.status is FindingStatus.GAP
    assert result.evidence["weak_policies"] == ["ExecRecording"]
    # Global default is compliant; the gap comes from the assigned custom policy alone.
    assert result.evidence["policies"]["Global"]["AllowCloudRecording"] is False


def test_weak_custom_broadcast_policy_is_gap() -> None:
    evidence = _demo()
    result = evaluate_teams_broadcast_not_always_record(
        _check("teams-broadcast-not-always-record"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert "AlwaysRecordEvents" in result.evidence["weak_policies"]


def test_weak_custom_app_policy_is_gap() -> None:
    evidence = _demo()
    result = evaluate_teams_microsoft_apps_governed(
        _check("teams-microsoft-apps-governed"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert "PowerUsers" in result.evidence["weak_policies"]


def test_anyone_link_checks_are_conditionally_not_applicable() -> None:
    evidence = _demo()
    assert (
        evaluate_spo_anyone_link_expiration(_check("spo-anyone-link-expiration"), evidence).status
        is FindingStatus.SKIPPED
    )
    assert (
        evaluate_spo_anyone_link_view(_check("spo-anyone-link-view"), evidence).status
        is FindingStatus.SKIPPED
    )


def test_anyone_link_checks_evaluate_when_anyone_enabled() -> None:
    evidence = _demo()
    _set_spo_capability(evidence, "ExternalUserAndGuestSharing")
    assert (
        evaluate_spo_anyone_link_expiration(_check("spo-anyone-link-expiration"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_spo_anyone_link_view(_check("spo-anyone-link-view"), evidence).status
        is FindingStatus.OK
    )


def test_anyone_link_expiration_gap_when_too_long() -> None:
    evidence = _demo()
    _set_spo_capability(evidence, "ExternalUserAndGuestSharing")
    _set_spo_prop(evidence, "anyone_link_expiration", "RequireAnonymousLinksExpireInDays", 0)
    result = evaluate_spo_anyone_link_expiration(_check("spo-anyone-link-expiration"), evidence)
    assert result.status is FindingStatus.GAP


def test_domain_restriction_not_applicable_when_sharing_disabled() -> None:
    evidence = _demo()
    _set_spo_capability(evidence, "Disabled")
    result = evaluate_spo_domain_restrictions(_check("spo-domain-restrictions"), evidence)
    assert result.status is FindingStatus.SKIPPED


def test_domain_allowlist_flags_unapproved_partner_domain() -> None:
    evidence = _demo()
    evidence["approved_partner_domains"] = ["contoso.com"]
    # fixture allowlist is "contoso.com partner.gov"; partner.gov is not approved here.
    result = evaluate_spo_domain_restrictions(_check("spo-domain-restrictions"), evidence)
    assert result.status is FindingStatus.GAP
    assert result.evidence["unapproved_domains"] == ["partner.gov"]


def test_domain_blocklist_mode_is_gap() -> None:
    evidence = _demo()
    _set_spo_prop(evidence, "domain_restrictions", "SharingDomainRestrictionMode", "BlockList")
    result = evaluate_spo_domain_restrictions(_check("spo-domain-restrictions"), evidence)
    assert result.status is FindingStatus.GAP


def test_unsupported_cloud_surfaces_are_not_false_gaps() -> None:
    evidence = _demo()
    for adapter, surface_name in (
        ("teams_federation", "unmanaged_users"),
        ("teams_client", "email_integration"),
    ):
        _surface(evidence["collaboration_bundle"], adapter, surface_name)["status"] = "unsupported"
        _surface(evidence["collaboration_bundle"], adapter, surface_name)["items"] = []
    assert (
        evaluate_teams_unmanaged_inbound_blocked(
            _check("teams-unmanaged-inbound-blocked"), evidence
        ).status
        is FindingStatus.SKIPPED
    )
    assert (
        evaluate_teams_email_integration_disabled(
            _check("teams-email-integration-disabled"), evidence
        ).status
        is FindingStatus.SKIPPED
    )


def test_malformed_collaboration_bundle_is_partial_not_ok() -> None:
    result = evaluate_spo_sharing_capability_limited(
        _check("spo-sharing-capability-limited"),
        {"collaboration_bundle": "not-a-dict"},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK


def test_empty_meeting_policy_is_partial_not_ok() -> None:
    evidence = _demo()
    _surface(evidence["collaboration_bundle"], "teams_meeting", "meeting_policies")["items"] = []
    result = evaluate_teams_recording_disabled(_check("teams-recording-disabled"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK


def test_denied_surface_is_partial_not_false_gap() -> None:
    evidence = _demo()
    _surface(evidence["collaboration_bundle"], "spo_tenant", "sharing_capability")["status"] = (
        "denied"
    )
    result = evaluate_spo_sharing_capability_limited(
        _check("spo-sharing-capability-limited"), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.GAP


def test_spo_unmanaged_device_access_blocked_ok() -> None:
    evidence = _demo()
    result = evaluate_spo_unmanaged_device_access(_check("spo-unmanaged-device-access"), evidence)
    assert result.status is FindingStatus.OK
    assert result.evidence["unmanaged_device_policy"] == "blockaccess"


def test_spo_unmanaged_device_access_full_access_gap() -> None:
    evidence = _demo()
    _set_spo_prop(evidence, "unmanaged_device_policy", "ConditionalAccessPolicy", "AllowFullAccess")
    result = evaluate_spo_unmanaged_device_access(_check("spo-unmanaged-device-access"), evidence)
    assert result.status is FindingStatus.GAP
    assert result.status is not FindingStatus.OK


def test_spo_unmanaged_device_access_missing_value_partial() -> None:
    evidence = _demo()
    _set_spo_prop(evidence, "unmanaged_device_policy", "ConditionalAccessPolicy", "")
    result = evaluate_spo_unmanaged_device_access(_check("spo-unmanaged-device-access"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK


def test_teams_guest_access_disabled_ok() -> None:
    evidence = _demo()
    result = evaluate_teams_guest_access_restricted(
        _check("teams-guest-access-restricted"), evidence
    )
    assert result.status is FindingStatus.OK
    assert result.evidence["allow_guest_user"] is False


def test_teams_guest_access_wide_open_gap() -> None:
    evidence = _demo()
    item = _surface(evidence["collaboration_bundle"], "teams_client", "guest_access")["items"][0]
    item["properties"]["AllowGuestUser"] = True
    item["properties"]["AllowGuestChat"] = True
    result = evaluate_teams_guest_access_restricted(
        _check("teams-guest-access-restricted"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.status is not FindingStatus.OK


def test_teams_guest_access_enabled_but_restricted_partial() -> None:
    evidence = _demo()
    item = _surface(evidence["collaboration_bundle"], "teams_client", "guest_access")["items"][0]
    item["properties"]["AllowGuestUser"] = True
    result = evaluate_teams_guest_access_restricted(
        _check("teams-guest-access-restricted"), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK


def test_all_collaboration_checks_resolve_via_registry() -> None:
    from licenselens.engine.registry import default_registry
    from licenselens.schema_contracts import EvaluationMode

    registry = default_registry()
    collaboration_ids = {
        check.id for check in load_checks() if check.workload is Workload.COLLABORATION
    }
    assert len(collaboration_ids) == 24
    for check_id in collaboration_ids:
        entry = registry.evaluator_for(check_id)
        assert entry.evaluation_mode is EvaluationMode.DIRECT
        assert entry.input_models == ("collaboration_bundle",)


def test_demo_evidence_is_deep_copied_between_builds() -> None:
    first = _demo()
    second = _demo()
    _set_spo_capability(first, "ExternalUserAndGuestSharing")
    assert first["collaboration_bundle"] != second["collaboration_bundle"]
    second_result = evaluate_spo_anyone_link_expiration(
        _check("spo-anyone-link-expiration"), second
    )
    assert second_result.status is FindingStatus.SKIPPED

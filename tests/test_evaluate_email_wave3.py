"""Wave 3 Exchange Online and Security Suite evaluator coverage."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from licenselens.collectors.dns_records import DEMO_DNS_RECORDS, parse_dmarc, parse_spf
from licenselens.collectors.exchange import demo_exchange_evidence
from licenselens.engine.evaluate import (
    evaluate_exo_dkim_enabled,
    evaluate_exo_dmarc_agency_contact,
    evaluate_exo_dmarc_federal_contact,
    evaluate_exo_dmarc_published,
    evaluate_exo_dmarc_reject,
    evaluate_exo_forwarding_external_disabled,
    evaluate_exo_mailbox_audit_enabled,
    evaluate_exo_smtp_auth_disabled,
    evaluate_exo_spf_published,
    evaluate_mdo_anti_spam_no_allowed_domains,
    evaluate_mdo_connection_filter_no_ip_allow,
    evaluate_mdo_impersonation_users_protected,
    evaluate_mdo_malware_file_filter,
    evaluate_mdo_p2_policies,
    evaluate_mdo_safe_attachments_spo_teams,
    evaluate_mdo_safe_links_block_list,
    evaluate_mdo_spam_phish_not_inbox,
    evaluate_pur_dlp_policy_present,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload


def _check(check_id: str, workload: Workload = Workload.EXCHANGE) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=workload)


def _demo() -> dict[str, Any]:
    evidence = demo_exchange_evidence()
    evidence["dns_records"] = deepcopy(DEMO_DNS_RECORDS)
    evidence["sensitive_users"] = ["ceo@contoso.com"]
    evidence["sensitive_domains"] = ["partner.example.com"]
    evidence["allowed_forwarding_domains"] = []
    evidence["dmarc_agency_contact"] = "reports@contoso.com"
    evidence["dmarc_federal_contact"] = ""
    return evidence


def _set_surface_prop(
    evidence: dict[str, Any],
    adapter: str,
    surface: str,
    prop_name: str,
    value: object,
) -> None:
    bundle = evidence["exchange_bundle"]
    item = bundle["adapters"][adapter]["surfaces"][surface]["items"][0]
    item["properties"][prop_name] = value


def test_demo_matrix_direct_and_dns_ok() -> None:
    evidence = _demo()
    assert (
        evaluate_exo_forwarding_external_disabled(
            _check("exo-forwarding-external-disabled"), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_exo_spf_published(_check("exo-spf-published"), evidence).status is FindingStatus.OK
    )
    assert (
        evaluate_exo_dkim_enabled(_check("exo-dkim-enabled"), evidence).status is FindingStatus.OK
    )
    assert (
        evaluate_exo_dmarc_published(_check("exo-dmarc-published"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_exo_dmarc_reject(_check("exo-dmarc-reject"), evidence).status is FindingStatus.OK
    )
    assert (
        evaluate_exo_smtp_auth_disabled(_check("exo-smtp-auth-disabled"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_exo_mailbox_audit_enabled(_check("exo-mailbox-audit-enabled"), evidence).status
        is FindingStatus.OK
    )
    assert (
        evaluate_mdo_malware_file_filter(
            _check("mdo-malware-file-filter", Workload.DEFENDER), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_mdo_safe_attachments_spo_teams(
            _check("mdo-safe-attachments-spo-teams", Workload.DEFENDER), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_mdo_safe_links_block_list(
            _check("mdo-safe-links-block-list", Workload.DEFENDER), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_mdo_spam_phish_not_inbox(
            _check("mdo-spam-phish-not-inbox", Workload.DEFENDER), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_pur_dlp_policy_present(
            _check("pur-dlp-policy-present", Workload.PURVIEW), evidence
        ).status
        is FindingStatus.OK
    )
    assert (
        evaluate_mdo_p2_policies(
            _check("mdo-p2-policies-default", Workload.DEFENDER), evidence
        ).evidence.get("proxy")
        is False
    )


def test_split_dns_spf_gap_for_one_domain() -> None:
    evidence = _demo()
    records = evidence["dns_records"]["records"]
    records["fabrikam.com"] = {
        "domain": "fabrikam.com",
        "spf": {
            "present": True,
            "hard_fail": False,
            "raw": ["v=spf1 include:spf.protection.outlook.com ?all"],
        },
        "dmarc": {
            "present": True,
            "policy": "reject",
            "rua": ["reports@contoso.com"],
            "ruf": [],
            "raw": ["v=DMARC1; p=reject"],
        },
        "error": None,
    }
    evidence["dns_records"]["domains"] = sorted(records)
    result = evaluate_exo_spf_published(_check("exo-spf-published"), evidence)
    assert result.status is FindingStatus.GAP
    assert "fabrikam.com" in result.evidence["spf_missing"]


def test_allowed_forwarding_exception_is_ok() -> None:
    evidence = _demo()
    _set_surface_prop(evidence, "exo_remote_domains", "remote_domains", "AutoForwardEnabled", True)
    _set_surface_prop(
        evidence, "exo_remote_domains", "remote_domains", "DomainName", "partner.example.com"
    )
    evidence["allowed_forwarding_domains"] = ["partner.example.com"]
    result = evaluate_exo_forwarding_external_disabled(
        _check("exo-forwarding-external-disabled"), evidence
    )
    assert result.status is FindingStatus.OK


def test_unapproved_forwarding_is_gap() -> None:
    evidence = _demo()
    _set_surface_prop(evidence, "exo_remote_domains", "remote_domains", "AutoForwardEnabled", True)
    _set_surface_prop(evidence, "exo_remote_domains", "remote_domains", "DomainName", "*")
    evidence["allowed_forwarding_domains"] = []
    result = evaluate_exo_forwarding_external_disabled(
        _check("exo-forwarding-external-disabled"), evidence
    )
    assert result.status is FindingStatus.GAP


def test_missing_sensitive_users_skips_impersonation() -> None:
    evidence = _demo()
    evidence["sensitive_users"] = []
    result = evaluate_mdo_impersonation_users_protected(
        _check("mdo-impersonation-users-protected", Workload.DEFENDER), evidence
    )
    assert result.status is FindingStatus.SKIPPED


def test_federal_dmarc_contact_profile_gated() -> None:
    evidence = _demo()
    empty = evaluate_exo_dmarc_federal_contact(_check("exo-dmarc-federal-contact"), evidence)
    assert empty.status is FindingStatus.SKIPPED
    evidence["dmarc_federal_contact"] = "reports@dmarc.cyber.dhs.gov"
    missing = evaluate_exo_dmarc_federal_contact(_check("exo-dmarc-federal-contact"), evidence)
    assert missing.status is FindingStatus.GAP
    evidence["dns_records"]["records"]["contoso.com"]["dmarc"]["rua"] = [
        "reports@dmarc.cyber.dhs.gov"
    ]
    ok = evaluate_exo_dmarc_federal_contact(_check("exo-dmarc-federal-contact"), evidence)
    assert ok.status is FindingStatus.OK


def test_agency_dmarc_contact_ok_on_demo() -> None:
    evidence = _demo()
    result = evaluate_exo_dmarc_agency_contact(_check("exo-dmarc-agency-contact"), evidence)
    assert result.status is FindingStatus.OK


def test_proxy_only_mdo_cannot_pass_as_ok() -> None:
    result = evaluate_mdo_p2_policies(
        _check("mdo-p2-policies-default", Workload.DEFENDER),
        {
            "exchange_threat_usable": False,
            "secure_score_controls": [
                {
                    "controlName": "mdo_safe_links",
                    "title": "Safe Links",
                    "scoreInPercentage": 100.0,
                    "count": 1,
                    "total": 1,
                },
                {
                    "controlName": "mdo_safe_attachments",
                    "title": "Safe Attachments",
                    "scoreInPercentage": 100.0,
                    "count": 1,
                    "total": 1,
                },
            ],
        },
    )
    assert result.status is not FindingStatus.OK
    assert result.evidence.get("proxy") is True


def test_anti_spam_allow_list_gap() -> None:
    evidence = _demo()
    _set_surface_prop(
        evidence, "exo_threat_policies", "anti_spam", "AllowedSenderDomains", ["evil.example"]
    )
    result = evaluate_mdo_anti_spam_no_allowed_domains(
        _check("mdo-anti-spam-no-allowed-domains", Workload.DEFENDER), evidence
    )
    assert result.status is FindingStatus.GAP


def test_connection_filter_ip_allow_gap() -> None:
    evidence = _demo()
    _set_surface_prop(
        evidence, "exo_threat_policies", "connection_filter", "IPAllowList", ["1.2.3.4"]
    )
    result = evaluate_mdo_connection_filter_no_ip_allow(
        _check("mdo-connection-filter-no-ip-allow", Workload.DEFENDER), evidence
    )
    assert result.status is FindingStatus.GAP


def test_dns_parser_hard_fail_and_dmarc_policy() -> None:
    spf = parse_spf(("v=spf1 include:spf.protection.outlook.com -all",))
    assert spf.present and spf.hard_fail
    dmarc = parse_dmarc(("v=DMARC1; p=quarantine; rua=mailto:a@example.com,mailto:b@example.com",))
    assert dmarc.present
    assert dmarc.policy == "quarantine"
    assert "a@example.com" in dmarc.rua


def test_malformed_exchange_bundle_is_partial_not_ok() -> None:
    result = evaluate_exo_smtp_auth_disabled(
        _check("exo-smtp-auth-disabled"),
        {"exchange_bundle": {"adapters": "not-a-dict"}},
    )
    assert result.status is FindingStatus.PARTIAL
    assert result.status is not FindingStatus.OK

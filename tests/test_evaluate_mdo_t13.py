"""Task 13 email/MDO checks: outbound spam forwarding, mailbox intelligence, transport rules."""

from __future__ import annotations

from typing import Any

from licenselens.collectors.exchange import demo_exchange_evidence
from licenselens.engine.evaluate import (
    evaluate_mdo_mailbox_intelligence,
    evaluate_mdo_outbound_spam_forwarding_block,
    evaluate_mdo_transport_rule_external_forward,
)
from licenselens.models import CheckDefinition, FindingStatus, Workload


def _check(check_id: str) -> CheckDefinition:
    return CheckDefinition(id=check_id, title=check_id, workload=Workload.DEFENDER)


def _demo() -> dict[str, Any]:
    return demo_exchange_evidence()


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


def _set_surface_status(evidence: dict[str, Any], adapter: str, surface: str, status: str) -> None:
    bundle = evidence["exchange_bundle"]
    bundle["adapters"][adapter]["surfaces"][surface]["status"] = status


def _add_transport_rule(evidence: dict[str, Any], name: str, properties: dict[str, object]) -> None:
    bundle = evidence["exchange_bundle"]
    items = bundle["adapters"]["exo_transport"]["surfaces"]["transport_rules"]["items"]
    items.append(
        {
            "name": name,
            "identity": name,
            "kind": "custom",
            "enabled": True,
            "properties": properties,
            "assignments": [],
        }
    )


# --- mdo-outbound-spam-forwarding-block -----------------------------------------------------


def test_outbound_spam_forwarding_blocked_is_ok() -> None:
    result = evaluate_mdo_outbound_spam_forwarding_block(
        _check("mdo-outbound-spam-forwarding-block"), _demo()
    )
    assert result.status is FindingStatus.OK


def test_outbound_spam_forwarding_enabled_is_gap() -> None:
    evidence = _demo()
    _set_surface_prop(
        evidence, "exo_threat_policies", "outbound_spam", "AutoForwardingEnabled", True
    )
    result = evaluate_mdo_outbound_spam_forwarding_block(
        _check("mdo-outbound-spam-forwarding-block"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert result.evidence["forwarding_enabled"]


def test_outbound_spam_surface_unreadable_is_partial() -> None:
    evidence = _demo()
    _set_surface_status(evidence, "exo_threat_policies", "outbound_spam", "denied")
    result = evaluate_mdo_outbound_spam_forwarding_block(
        _check("mdo-outbound-spam-forwarding-block"), evidence
    )
    assert result.status is FindingStatus.PARTIAL


# --- mdo-mailbox-intelligence ---------------------------------------------------------------


def test_mailbox_intelligence_enabled_is_ok() -> None:
    result = evaluate_mdo_mailbox_intelligence(_check("mdo-mailbox-intelligence"), _demo())
    assert result.status is FindingStatus.OK


def test_mailbox_intelligence_disabled_is_gap() -> None:
    evidence = _demo()
    _set_surface_prop(
        evidence, "exo_threat_policies", "anti_phish", "EnableMailboxIntelligence", False
    )
    result = evaluate_mdo_mailbox_intelligence(_check("mdo-mailbox-intelligence"), evidence)
    assert result.status is FindingStatus.GAP
    assert result.evidence["mailbox_intelligence_missing"]


def test_mailbox_intelligence_mixed_policies_is_partial() -> None:
    evidence = _demo()
    bundle = evidence["exchange_bundle"]
    anti_phish = bundle["adapters"]["exo_threat_policies"]["surfaces"]["anti_phish"]["items"]
    anti_phish.append(
        {
            "name": "Finance AntiPhish",
            "identity": "Finance AntiPhish",
            "kind": "custom",
            "enabled": True,
            "properties": {"EnableMailboxIntelligence": False},
            "assignments": [],
        }
    )
    result = evaluate_mdo_mailbox_intelligence(_check("mdo-mailbox-intelligence"), evidence)
    assert result.status is FindingStatus.PARTIAL
    assert "Finance AntiPhish" in result.evidence["mailbox_intelligence_missing"]


def test_mailbox_intelligence_surface_unreadable_is_partial() -> None:
    evidence = _demo()
    _set_surface_status(evidence, "exo_threat_policies", "anti_phish", "denied")
    result = evaluate_mdo_mailbox_intelligence(_check("mdo-mailbox-intelligence"), evidence)
    assert result.status is FindingStatus.PARTIAL


# --- mdo-transport-rule-external-forward ----------------------------------------------------


def test_transport_rules_without_external_forward_are_ok() -> None:
    result = evaluate_mdo_transport_rule_external_forward(
        _check("mdo-transport-rule-external-forward"), _demo()
    )
    assert result.status is FindingStatus.OK


def test_transport_rule_redirect_external_is_gap() -> None:
    evidence = _demo()
    _add_transport_rule(evidence, "Silent exfil", {"RedirectMessageTo": ["attacker@evil.example"]})
    result = evaluate_mdo_transport_rule_external_forward(
        _check("mdo-transport-rule-external-forward"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert "Silent exfil" in result.evidence["external_forward_rules"]


def test_transport_rule_bcc_external_is_gap() -> None:
    evidence = _demo()
    _add_transport_rule(evidence, "Quiet copy", {"BlindCopyTo": ["watch@outside.example"]})
    result = evaluate_mdo_transport_rule_external_forward(
        _check("mdo-transport-rule-external-forward"), evidence
    )
    assert result.status is FindingStatus.GAP
    assert "Quiet copy" in result.evidence["external_forward_rules"]


def test_transport_rule_internal_redirect_is_ok() -> None:
    evidence = _demo()
    _add_transport_rule(evidence, "Internal review", {"RedirectMessageTo": ["audit@contoso.com"]})
    result = evaluate_mdo_transport_rule_external_forward(
        _check("mdo-transport-rule-external-forward"), evidence
    )
    assert result.status is FindingStatus.OK


def test_transport_rule_forward_without_accepted_domains_is_partial() -> None:
    evidence = _demo()
    _add_transport_rule(
        evidence, "Unknown target", {"RedirectMessageTo": ["someone@somewhere.example"]}
    )
    _set_surface_status(evidence, "exo_accepted_domains", "accepted_domains", "denied")
    result = evaluate_mdo_transport_rule_external_forward(
        _check("mdo-transport-rule-external-forward"), evidence
    )
    assert result.status is FindingStatus.PARTIAL
    assert "Unknown target" in result.evidence["unresolved_rules"]


def test_transport_rule_surface_unreadable_is_partial() -> None:
    evidence = _demo()
    _set_surface_status(evidence, "exo_transport", "transport_rules", "denied")
    result = evaluate_mdo_transport_rule_external_forward(
        _check("mdo-transport-rule-external-forward"), evidence
    )
    assert result.status is FindingStatus.PARTIAL

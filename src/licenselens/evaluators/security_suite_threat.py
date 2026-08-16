"""Defender for Office threat-policy evaluators (malware, Safe Links/Attachments, impersonation)."""

from __future__ import annotations

from licenselens.evaluators.security_suite_threat_impersonation import (
    evaluate_mdo_impersonation_domains_owned,
    evaluate_mdo_impersonation_partner_domains,
    evaluate_mdo_impersonation_users_protected,
    evaluate_mdo_safety_tips_enabled,
)
from licenselens.evaluators.security_suite_threat_malware import (
    evaluate_mdo_malware_file_filter,
    evaluate_mdo_malware_zap,
    evaluate_mdo_quarantine_policy,
    evaluate_mdo_safe_attachments_block,
    evaluate_mdo_safe_links_block_list,
    evaluate_mdo_safe_links_click_through,
    evaluate_mdo_safe_links_click_tracking,
    evaluate_mdo_safe_links_real_time_scan,
)

__all__ = [
    "evaluate_mdo_impersonation_domains_owned",
    "evaluate_mdo_impersonation_partner_domains",
    "evaluate_mdo_impersonation_users_protected",
    "evaluate_mdo_malware_file_filter",
    "evaluate_mdo_malware_zap",
    "evaluate_mdo_quarantine_policy",
    "evaluate_mdo_safe_attachments_block",
    "evaluate_mdo_safe_links_block_list",
    "evaluate_mdo_safe_links_click_through",
    "evaluate_mdo_safe_links_click_tracking",
    "evaluate_mdo_safe_links_real_time_scan",
    "evaluate_mdo_safety_tips_enabled",
]

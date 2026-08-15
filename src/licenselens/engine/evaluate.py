"""Compatibility exports for evaluator imports during the split release."""

from __future__ import annotations

from licenselens.evaluators.azure_selective import (
    evaluate_az_cspm_out_of_scope,
    evaluate_az_defender_plan_enabled,
)
from licenselens.evaluators.collaboration_sharing import (
    evaluate_spo_domain_restrictions,
    evaluate_spo_onedrive_sharing_limited,
    evaluate_spo_sharing_capability_limited,
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
from licenselens.evaluators.common import Evaluation, Evaluator
from licenselens.evaluators.defender import evaluate_mdi_sensors
from licenselens.evaluators.defender_endpoint import evaluate_mde_onboard_gap
from licenselens.evaluators.defender_mdo import evaluate_mdo_p2_policies
from licenselens.evaluators.endpoint_intune import (
    evaluate_endpoint_compliance_noncompliance_action,
    evaluate_endpoint_compliance_policy_assigned,
    evaluate_endpoint_enrollment_coverage,
)
from licenselens.evaluators.endpoint_intune_policy import (
    evaluate_endpoint_mde_connector,
    evaluate_endpoint_security_baseline,
    evaluate_endpoint_security_policy_coverage,
)
from licenselens.evaluators.endpoint_mde_xdr import (
    evaluate_mde_sensor_health,
    evaluate_xdr_incident_readiness,
)
from licenselens.evaluators.exchange_email_auth import (
    evaluate_exo_dkim_enabled,
    evaluate_exo_dmarc_agency_contact,
    evaluate_exo_dmarc_federal_contact,
    evaluate_exo_dmarc_published,
    evaluate_exo_dmarc_reject,
    evaluate_exo_spf_published,
)
from licenselens.evaluators.exchange_mailflow import (
    evaluate_exo_external_sender_warnings,
    evaluate_exo_forwarding_external_disabled,
    evaluate_exo_mailbox_audit_enabled,
    evaluate_exo_sharing_calendar_not_all_domains,
    evaluate_exo_sharing_contact_not_all_domains,
    evaluate_exo_smtp_auth_disabled,
)
from licenselens.evaluators.identity_access import evaluate_ca_priv_gaps
from licenselens.evaluators.identity_apps_consent import (
    evaluate_app_admin_consent_workflow,
    evaluate_app_password_addition_blocked,
    evaluate_app_registration_admin_only,
    evaluate_app_risky_delegated_consent,
    evaluate_app_user_consent_restricted,
)
from licenselens.evaluators.identity_apps_credentials import (
    evaluate_app_certificate_lifetime,
    evaluate_app_expiring_credentials,
    evaluate_app_ownerless_or_stale,
    evaluate_app_password_lifetime,
)
from licenselens.evaluators.identity_auth_methods import (
    evaluate_auth_authenticator_context,
    evaluate_auth_methods_migration,
    evaluate_auth_weak_methods_disabled,
)
from licenselens.evaluators.identity_ca_coverage import (
    evaluate_ca_device_code_block,
    evaluate_ca_legacy_auth_block,
    evaluate_ca_managed_devices,
    evaluate_ca_mfa_all_users,
    evaluate_ca_mfa_registration_managed,
    evaluate_ca_phishing_resistant_all,
    evaluate_ca_phishing_resistant_privileged,
)
from licenselens.evaluators.identity_ca_risk import (
    evaluate_ca_high_risk_signins,
    evaluate_ca_high_risk_users,
)
from licenselens.evaluators.identity_governance import (
    evaluate_access_reviews_unused,
    evaluate_security_defaults_on,
)
from licenselens.evaluators.identity_guests import (
    evaluate_cross_tenant_defaults,
    evaluate_guest_directory_access_limited,
    evaluate_guest_invite_domains,
    evaluate_guest_inviter_restricted,
)
from licenselens.evaluators.identity_manual import (
    evaluate_ai_agents_risky_block,
    evaluate_idprotect_notify_high_risk,
    evaluate_logs_to_soc,
)
from licenselens.evaluators.identity_pim_rules import (
    evaluate_pim_ga_activation_alert,
    evaluate_pim_ga_activation_approval,
    evaluate_pim_no_outside_pam,
    evaluate_pim_no_permanent_privileged,
    evaluate_pim_other_activation_alert,
    evaluate_pim_privileged_assignment_alert,
)
from licenselens.evaluators.identity_privileged import (
    evaluate_dormant_privileged,
    evaluate_pim_unused,
)
from licenselens.evaluators.identity_privileged_extra import (
    evaluate_ga_count_bounds,
    evaluate_ga_finer_roles,
    evaluate_password_never_expire,
    evaluate_priv_cloud_only,
)
from licenselens.evaluators.identity_risk import evaluate_idprotect_off
from licenselens.evaluators.power_bi import (
    evaluate_pbi_external_invite_disabled,
    evaluate_pbi_guest_access_disabled,
    evaluate_pbi_publish_to_web_disabled,
    evaluate_pbi_python_r_visuals_disabled,
    evaluate_pbi_resource_key_auth_blocked,
    evaluate_pbi_sensitivity_labels_enabled,
    evaluate_pbi_sp_api_restricted,
    evaluate_pbi_sp_profiles_disabled,
)
from licenselens.evaluators.power_platform_env import (
    evaluate_pp_dlp_all_environments,
    evaluate_pp_tenant_isolation_enabled,
)
from licenselens.evaluators.power_platform_tenant import (
    evaluate_pp_env_creation_admin_only,
    evaluate_pp_pages_creation_admin_only,
    evaluate_pp_share_with_everyone_disabled,
    evaluate_pp_trial_creation_admin_only,
)
from licenselens.evaluators.purview import evaluate_purview_dlp
from licenselens.evaluators.purview_governance import (
    evaluate_pur_retention_policy_coverage,
    evaluate_pur_sensitivity_auto_labeling,
    evaluate_pur_sensitivity_labels_published,
)
from licenselens.evaluators.purview_manual import (
    evaluate_pur_communication_compliance_readiness,
    evaluate_pur_ediscovery_readiness,
    evaluate_pur_insider_risk_readiness,
)
from licenselens.evaluators.security_suite_dlp import (
    evaluate_mdo_unified_audit_enabled,
    evaluate_pur_dlp_enforcement_block,
    evaluate_pur_dlp_locations_complete,
    evaluate_pur_dlp_notifications,
    evaluate_pur_dlp_policy_present,
)
from licenselens.evaluators.security_suite_spam import (
    evaluate_mdo_alert_policies_manual,
    evaluate_mdo_anti_spam_no_allowed_domains,
    evaluate_mdo_audit_retention_manual,
    evaluate_mdo_connection_filter_no_ip_allow,
    evaluate_mdo_connection_filter_no_safe_list,
    evaluate_mdo_safe_attachments_spo_teams,
    evaluate_mdo_spam_phish_not_inbox,
)
from licenselens.evaluators.security_suite_threat import (
    evaluate_mdo_impersonation_domains_owned,
    evaluate_mdo_impersonation_partner_domains,
    evaluate_mdo_impersonation_users_protected,
    evaluate_mdo_malware_file_filter,
    evaluate_mdo_malware_zap,
    evaluate_mdo_safe_attachments_block,
    evaluate_mdo_safe_links_block_list,
    evaluate_mdo_safe_links_click_tracking,
    evaluate_mdo_safe_links_real_time_scan,
    evaluate_mdo_safety_tips_enabled,
)
from licenselens.evaluators.sentinel import (
    evaluate_sen_analytics_coverage,
    evaluate_sen_ueba,
)
from licenselens.evaluators.sentinel_extended import (
    evaluate_sen_automation_rules,
    evaluate_sen_data_connectors,
    evaluate_sen_log_analytics_retention,
)

__all__ = [
    "Evaluation",
    "Evaluator",
    "evaluate_az_cspm_out_of_scope",
    "evaluate_az_defender_plan_enabled",
    "evaluate_spo_domain_restrictions",
    "evaluate_spo_onedrive_sharing_limited",
    "evaluate_spo_sharing_capability_limited",
    "evaluate_spo_anyone_link_expiration",
    "evaluate_spo_anyone_link_view",
    "evaluate_spo_default_link_specific",
    "evaluate_spo_default_link_view",
    "evaluate_spo_verification_reauth",
    "evaluate_teams_email_integration_disabled",
    "evaluate_teams_external_access_per_domain",
    "evaluate_teams_unmanaged_inbound_blocked",
    "evaluate_teams_unmanaged_outbound_blocked",
    "evaluate_teams_custom_apps_governed",
    "evaluate_teams_microsoft_apps_governed",
    "evaluate_teams_third_party_apps_governed",
    "evaluate_teams_anonymous_lobby",
    "evaluate_teams_anonymous_start_disabled",
    "evaluate_teams_broadcast_not_always_record",
    "evaluate_teams_dialin_lobby",
    "evaluate_teams_external_control_disabled",
    "evaluate_teams_internal_auto_admit",
    "evaluate_teams_recording_disabled",
    "evaluate_mdi_sensors",
    "evaluate_mde_onboard_gap",
    "evaluate_mdo_p2_policies",
    "evaluate_endpoint_compliance_noncompliance_action",
    "evaluate_endpoint_compliance_policy_assigned",
    "evaluate_endpoint_enrollment_coverage",
    "evaluate_endpoint_mde_connector",
    "evaluate_endpoint_security_baseline",
    "evaluate_endpoint_security_policy_coverage",
    "evaluate_mde_sensor_health",
    "evaluate_xdr_incident_readiness",
    "evaluate_exo_dkim_enabled",
    "evaluate_exo_dmarc_agency_contact",
    "evaluate_exo_dmarc_federal_contact",
    "evaluate_exo_dmarc_published",
    "evaluate_exo_dmarc_reject",
    "evaluate_exo_spf_published",
    "evaluate_exo_external_sender_warnings",
    "evaluate_exo_forwarding_external_disabled",
    "evaluate_exo_mailbox_audit_enabled",
    "evaluate_exo_sharing_calendar_not_all_domains",
    "evaluate_exo_sharing_contact_not_all_domains",
    "evaluate_exo_smtp_auth_disabled",
    "evaluate_ca_priv_gaps",
    "evaluate_app_admin_consent_workflow",
    "evaluate_app_password_addition_blocked",
    "evaluate_app_registration_admin_only",
    "evaluate_app_risky_delegated_consent",
    "evaluate_app_user_consent_restricted",
    "evaluate_app_certificate_lifetime",
    "evaluate_app_expiring_credentials",
    "evaluate_app_ownerless_or_stale",
    "evaluate_app_password_lifetime",
    "evaluate_auth_authenticator_context",
    "evaluate_auth_methods_migration",
    "evaluate_auth_weak_methods_disabled",
    "evaluate_ca_device_code_block",
    "evaluate_ca_legacy_auth_block",
    "evaluate_ca_managed_devices",
    "evaluate_ca_mfa_all_users",
    "evaluate_ca_mfa_registration_managed",
    "evaluate_ca_phishing_resistant_all",
    "evaluate_ca_phishing_resistant_privileged",
    "evaluate_ca_high_risk_signins",
    "evaluate_ca_high_risk_users",
    "evaluate_access_reviews_unused",
    "evaluate_security_defaults_on",
    "evaluate_cross_tenant_defaults",
    "evaluate_guest_directory_access_limited",
    "evaluate_guest_invite_domains",
    "evaluate_guest_inviter_restricted",
    "evaluate_ai_agents_risky_block",
    "evaluate_idprotect_notify_high_risk",
    "evaluate_logs_to_soc",
    "evaluate_pim_ga_activation_alert",
    "evaluate_pim_ga_activation_approval",
    "evaluate_pim_no_outside_pam",
    "evaluate_pim_no_permanent_privileged",
    "evaluate_pim_other_activation_alert",
    "evaluate_pim_privileged_assignment_alert",
    "evaluate_dormant_privileged",
    "evaluate_pim_unused",
    "evaluate_ga_count_bounds",
    "evaluate_ga_finer_roles",
    "evaluate_password_never_expire",
    "evaluate_priv_cloud_only",
    "evaluate_idprotect_off",
    "evaluate_pbi_external_invite_disabled",
    "evaluate_pbi_guest_access_disabled",
    "evaluate_pbi_publish_to_web_disabled",
    "evaluate_pbi_python_r_visuals_disabled",
    "evaluate_pbi_resource_key_auth_blocked",
    "evaluate_pbi_sensitivity_labels_enabled",
    "evaluate_pbi_sp_api_restricted",
    "evaluate_pbi_sp_profiles_disabled",
    "evaluate_pp_dlp_all_environments",
    "evaluate_pp_tenant_isolation_enabled",
    "evaluate_pp_env_creation_admin_only",
    "evaluate_pp_pages_creation_admin_only",
    "evaluate_pp_share_with_everyone_disabled",
    "evaluate_pp_trial_creation_admin_only",
    "evaluate_purview_dlp",
    "evaluate_pur_retention_policy_coverage",
    "evaluate_pur_sensitivity_auto_labeling",
    "evaluate_pur_sensitivity_labels_published",
    "evaluate_pur_communication_compliance_readiness",
    "evaluate_pur_ediscovery_readiness",
    "evaluate_pur_insider_risk_readiness",
    "evaluate_mdo_unified_audit_enabled",
    "evaluate_pur_dlp_enforcement_block",
    "evaluate_pur_dlp_locations_complete",
    "evaluate_pur_dlp_notifications",
    "evaluate_pur_dlp_policy_present",
    "evaluate_mdo_alert_policies_manual",
    "evaluate_mdo_anti_spam_no_allowed_domains",
    "evaluate_mdo_audit_retention_manual",
    "evaluate_mdo_connection_filter_no_ip_allow",
    "evaluate_mdo_connection_filter_no_safe_list",
    "evaluate_mdo_safe_attachments_spo_teams",
    "evaluate_mdo_spam_phish_not_inbox",
    "evaluate_mdo_impersonation_domains_owned",
    "evaluate_mdo_impersonation_partner_domains",
    "evaluate_mdo_impersonation_users_protected",
    "evaluate_mdo_malware_file_filter",
    "evaluate_mdo_malware_zap",
    "evaluate_mdo_safe_attachments_block",
    "evaluate_mdo_safe_links_block_list",
    "evaluate_mdo_safe_links_click_tracking",
    "evaluate_mdo_safe_links_real_time_scan",
    "evaluate_mdo_safety_tips_enabled",
    "evaluate_sen_analytics_coverage",
    "evaluate_sen_ueba",
    "evaluate_sen_automation_rules",
    "evaluate_sen_data_connectors",
    "evaluate_sen_log_analytics_retention",
]

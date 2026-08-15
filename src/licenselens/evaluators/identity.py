"""Identity workload evaluator exports."""

from __future__ import annotations

from licenselens.evaluators.identity_access import evaluate_ca_priv_gaps
from licenselens.evaluators.identity_apps import (
    evaluate_app_admin_consent_workflow,
    evaluate_app_certificate_lifetime,
    evaluate_app_expiring_credentials,
    evaluate_app_ownerless_or_stale,
    evaluate_app_password_addition_blocked,
    evaluate_app_password_lifetime,
    evaluate_app_registration_admin_only,
    evaluate_app_risky_delegated_consent,
    evaluate_app_user_consent_restricted,
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

__all__ = [
    "evaluate_access_reviews_unused",
    "evaluate_ai_agents_risky_block",
    "evaluate_app_admin_consent_workflow",
    "evaluate_app_certificate_lifetime",
    "evaluate_app_expiring_credentials",
    "evaluate_app_ownerless_or_stale",
    "evaluate_app_password_addition_blocked",
    "evaluate_app_password_lifetime",
    "evaluate_app_registration_admin_only",
    "evaluate_app_risky_delegated_consent",
    "evaluate_app_user_consent_restricted",
    "evaluate_auth_authenticator_context",
    "evaluate_auth_methods_migration",
    "evaluate_auth_weak_methods_disabled",
    "evaluate_ca_device_code_block",
    "evaluate_ca_high_risk_signins",
    "evaluate_ca_high_risk_users",
    "evaluate_ca_legacy_auth_block",
    "evaluate_ca_managed_devices",
    "evaluate_ca_mfa_all_users",
    "evaluate_ca_mfa_registration_managed",
    "evaluate_ca_phishing_resistant_all",
    "evaluate_ca_phishing_resistant_privileged",
    "evaluate_ca_priv_gaps",
    "evaluate_cross_tenant_defaults",
    "evaluate_dormant_privileged",
    "evaluate_ga_count_bounds",
    "evaluate_ga_finer_roles",
    "evaluate_guest_directory_access_limited",
    "evaluate_guest_invite_domains",
    "evaluate_guest_inviter_restricted",
    "evaluate_idprotect_notify_high_risk",
    "evaluate_idprotect_off",
    "evaluate_logs_to_soc",
    "evaluate_password_never_expire",
    "evaluate_pim_ga_activation_alert",
    "evaluate_pim_ga_activation_approval",
    "evaluate_pim_no_outside_pam",
    "evaluate_pim_no_permanent_privileged",
    "evaluate_pim_other_activation_alert",
    "evaluate_pim_privileged_assignment_alert",
    "evaluate_pim_unused",
    "evaluate_priv_cloud_only",
    "evaluate_security_defaults_on",
]

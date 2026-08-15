"""Application registration, consent, and credential evaluators."""

from __future__ import annotations

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

__all__ = [
    "evaluate_app_admin_consent_workflow",
    "evaluate_app_certificate_lifetime",
    "evaluate_app_expiring_credentials",
    "evaluate_app_ownerless_or_stale",
    "evaluate_app_password_addition_blocked",
    "evaluate_app_password_lifetime",
    "evaluate_app_registration_admin_only",
    "evaluate_app_risky_delegated_consent",
    "evaluate_app_user_consent_restricted",
]

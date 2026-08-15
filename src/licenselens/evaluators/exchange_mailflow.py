"""Exchange Online mail-flow evaluators (forwarding, SMTP AUTH, sharing, warnings, audit)."""

from __future__ import annotations

from licenselens.evaluators.exchange_mailflow_core import (
    evaluate_exo_forwarding_external_disabled,
    evaluate_exo_smtp_auth_disabled,
)
from licenselens.evaluators.exchange_mailflow_sharing import (
    evaluate_exo_external_sender_warnings,
    evaluate_exo_mailbox_audit_enabled,
    evaluate_exo_sharing_calendar_not_all_domains,
    evaluate_exo_sharing_contact_not_all_domains,
)

__all__ = [
    "evaluate_exo_external_sender_warnings",
    "evaluate_exo_forwarding_external_disabled",
    "evaluate_exo_mailbox_audit_enabled",
    "evaluate_exo_sharing_calendar_not_all_domains",
    "evaluate_exo_sharing_contact_not_all_domains",
    "evaluate_exo_smtp_auth_disabled",
]

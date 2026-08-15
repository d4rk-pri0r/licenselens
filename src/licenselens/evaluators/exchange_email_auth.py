"""Email-authentication evaluators (DKIM via PowerShell, SPF/DMARC via DNS)."""

from __future__ import annotations

from licenselens.evaluators.exchange_email_auth_dkim import evaluate_exo_dkim_enabled
from licenselens.evaluators.exchange_email_auth_dns import (
    evaluate_exo_dmarc_agency_contact,
    evaluate_exo_dmarc_federal_contact,
    evaluate_exo_dmarc_published,
    evaluate_exo_dmarc_reject,
    evaluate_exo_spf_published,
)

__all__ = [
    "evaluate_exo_dkim_enabled",
    "evaluate_exo_dmarc_agency_contact",
    "evaluate_exo_dmarc_federal_contact",
    "evaluate_exo_dmarc_published",
    "evaluate_exo_dmarc_reject",
    "evaluate_exo_spf_published",
]

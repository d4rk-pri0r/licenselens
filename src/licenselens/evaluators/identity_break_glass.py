"""Break-glass (emergency access) account evaluator."""

from __future__ import annotations

from typing import Any, Final

from licenselens.evaluators.common import Evaluation
from licenselens.evaluators.identity_ca_lib import (
    break_glass_principal_ids,
    exclusion_issues,
)
from licenselens.models import CheckDefinition, FindingStatus

_CANNOT_IDENTIFY_NOTE: Final = (
    "The break-glass account could not be confidently identified from the "
    "scanned Global Administrator assignments and eligibilities — verify the "
    "emergency access account in the Entra portal before relying on this check."
)


def _ga_principals(evidence: dict[str, Any]) -> set[str]:
    from licenselens.collectors import privileged_roles as priv

    assignments = list(evidence.get("role_assignments") or [])
    eligibilities = list(evidence.get("role_eligibilities") or [])
    ga = priv.GLOBAL_ADMIN_TEMPLATE_ID.lower()
    principals: set[str] = set()
    for row in (*assignments, *eligibilities):
        if str(row.get("roleDefinitionId") or "").lower() == ga:
            pid = row.get("principalId")
            if pid:
                principals.add(str(pid))
    return principals


def evaluate_break_glass_exclusion(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    """Break-glass account exists AND its Conditional Access exclusions are justified."""
    del check  # metadata unused; signature shared with registry
    from licenselens.collectors import conditional_access as ca

    policies: list[dict[str, Any]] = list(evidence.get("ca_policies") or [])
    justified = break_glass_principal_ids(evidence)
    ga_principals = _ga_principals(evidence)
    identified_break_glass = sorted(ga_principals & justified)

    enabled = [p for p in policies if ca.is_enabled(p)]
    report_only = [p for p in policies if ca.is_report_only(p)]
    enforced_with_grant = [p for p in enabled if ca.requires_mfa(p) or ca.is_block_policy(p)]
    exclusion_rows = exclusion_issues(enforced_with_grant + report_only, justified)
    unjustified_count = sum(len(row["unjustified_exclusions"]) for row in exclusion_rows)
    excluded_ga_rows = [
        row
        for row in exclusion_rows
        if any(principal in ga_principals for principal in row["unjustified_exclusions"])
    ]

    evidence_out = {
        "global_admin_principal_count": len(ga_principals),
        "declared_break_glass_principal_count": len(justified),
        "identified_break_glass_accounts": identified_break_glass,
        "enabled_ca_policy_count": len(enabled),
        "report_only_ca_policy_count": len(report_only),
        "unjustified_exclusion_issues": exclusion_rows,
        "unjustified_exclusion_count": unjustified_count,
        "global_admin_exclusion_issues": excluded_ga_rows,
    }

    limitations: list[str] = []

    if not ga_principals:
        if justified:
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    "Declared break-glass principals were not found among the "
                    "scanned Global Administrator assignments or eligibilities."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "Your assessment profile names emergency accounts, but we "
                    "could not match them to any Global Administrator account "
                    "we scanned — please verify the accounts exist."
                ),
                limitations=[_CANNOT_IDENTIFY_NOTE],
            )
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "No Global Administrator assignments or eligibilities were found, "
                "so no break-glass account could be identified."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not find any Global Administrator account that could "
                "serve as the emergency 'break-glass' login when normal admin "
                "access fails."
            ),
            limitations=[_CANNOT_IDENTIFY_NOTE],
        )

    if not identified_break_glass:
        limitations.append(_CANNOT_IDENTIFY_NOTE)
        if justified:
            exclusion_note = (
                f" Additionally, {unjustified_count} Conditional Access "
                "exclusion(s) lack a documented break-glass rationale."
                if unjustified_count
                else ""
            )
            return Evaluation(
                status=FindingStatus.PARTIAL,
                summary=(
                    f"{len(justified)} declared break-glass principal(s) did not "
                    f"match any scanned Global Administrator"
                    + exclusion_note
                ),
                evidence=evidence_out,
                customer_summary=(
                    "Your assessment profile names emergency accounts, but we "
                    "could not match them to a Global Administrator account we "
                    "scanned — please verify the accounts and their exclusions."
                ),
                limitations=limitations,
            )
        if unjustified_count:
            return Evaluation(
                status=FindingStatus.GAP,
                summary=(
                    "No break-glass account was identified, and Conditional "
                    "Access policies exclude Global Administrator principals "
                    "without a documented break-glass rationale."
                ),
                evidence=evidence_out,
                customer_summary=(
                    "We could not confirm which account is your emergency admin, "
                    "and some sign-in rules quietly skip Global Administrators "
                    "with no documented reason."
                ),
                limitations=limitations,
            )
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(
                "No break-glass account was identified among the Global "
                "Administrators; no principal is declared as break-glass in the "
                "assessment profile."
            ),
            evidence=evidence_out,
            customer_summary=(
                "We could not confirm a dedicated emergency admin account. "
                "Without one, an outage or lockout can lock you out of your own "
                "tenant."
            ),
            limitations=limitations,
        )

    if unjustified_count:
        return Evaluation(
            status=FindingStatus.PARTIAL,
            summary=(
                f"Break-glass account identified ({len(identified_break_glass)}), "
                f"but {unjustified_count} Conditional Access exclusion(s) are not "
                "covered by a documented break-glass rationale."
            ),
            evidence=evidence_out,
            customer_summary=(
                "Your emergency admin account is in place, but some accounts are "
                "excluded from sign-in rules without a documented emergency "
                "rationale — those accounts can still get in with less protection."
            ),
            limitations=limitations,
        )

    return Evaluation(
        status=FindingStatus.OK,
        summary=(
            f"Break-glass account identified ({len(identified_break_glass)} "
            "Global Administrator principal(s)) and all Conditional Access "
            "exclusions are justified."
        ),
        evidence=evidence_out,
        customer_summary=(
            "A dedicated emergency admin account is in place, and accounts "
            "excluded from your sign-in rules are documented as emergency access."
        ),
        limitations=limitations,
    )

"""Application registration and consent evaluators."""

from __future__ import annotations

from typing import Any, Final

from licenselens.collectors import conditional_access as ca
from licenselens.evaluators.common import Evaluation
from licenselens.models import CheckDefinition, FindingStatus

_RISKY_SCOPES: Final = frozenset(
    {
        "mail.read",
        "mail.readwrite",
        "files.read.write.all",
        "sites.read.write.all",
        "directory.readwrite.all",
        "user.readwrite.all",
        "rolemanagement.readwrite.directory",
    }
)


def _authz(evidence: dict[str, Any]) -> dict[str, Any]:
    policy = evidence.get("authorization_policy") or {}
    return policy if isinstance(policy, dict) else {}


def _grants(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    bundle = evidence.get("applications_bundle") or {}
    if isinstance(bundle, dict) and bundle.get("oauth2_permission_grants") is not None:
        return list(bundle.get("oauth2_permission_grants") or [])
    return list(evidence.get("oauth2_permission_grants") or [])


def _authz(evidence: dict[str, Any]) -> dict[str, Any]:
    policy = evidence.get("authorization_policy") or {}
    return policy if isinstance(policy, dict) else {}


def _grants(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    bundle = evidence.get("applications_bundle") or {}
    if isinstance(bundle, dict) and bundle.get("oauth2_permission_grants") is not None:
        return list(bundle.get("oauth2_permission_grants") or [])
    return list(evidence.get("oauth2_permission_grants") or [])


def evaluate_app_registration_admin_only(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policy = _authz(evidence)
    perms = policy.get("defaultUserRolePermissions") or {}
    allowed = bool(perms.get("allowedToCreateApps")) if isinstance(perms, dict) else True
    evidence_out = {"allowed_to_create_apps": allowed}
    if allowed:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="Non-admin users can register applications.",
            evidence=evidence_out,
            customer_summary=(
                "Anyone in the directory can create app registrations, which expands "
                "the attack surface for malicious apps."
            ),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="Only administrators can register applications.",
        evidence=evidence_out,
        customer_summary="Regular users cannot create new app registrations.",
    )


def evaluate_app_user_consent_restricted(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policy = _authz(evidence)
    perms = policy.get("defaultUserRolePermissions") or {}
    grants = list((perms or {}).get("permissionGrantPoliciesAssigned") or [])
    grant_text = " ".join(str(g).lower() for g in grants)
    unrestricted = (
        not grants or "microsoft-user-default-legacy" in grant_text or "managedown" in grant_text
    )
    evidence_out = {"permission_grant_policies": grants, "unrestricted": unrestricted}
    if unrestricted:
        return Evaluation(
            status=FindingStatus.GAP,
            summary="User consent to applications is not tightly restricted.",
            evidence=evidence_out,
            customer_summary=(
                "Users can still approve app permissions themselves, which is a common "
                "path for consent phishing."
            ),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="User consent to applications appears restricted.",
        evidence=evidence_out,
        customer_summary="Users cannot freely approve risky app permissions on their own.",
    )


def evaluate_app_admin_consent_workflow(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policy = evidence.get("admin_consent_request_policy") or {}
    if not isinstance(policy, dict):
        policy = {}
    enabled = bool(policy.get("isEnabled"))
    evidence_out = {
        "is_enabled": enabled,
        "notify_reviewers": bool(policy.get("notifyReviewers")),
    }
    if enabled:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Admin consent request workflow is enabled.",
            evidence=evidence_out,
            customer_summary=(
                "Users can request admin approval for apps instead of consenting alone."
            ),
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="Admin consent request workflow is not enabled.",
        evidence=evidence_out,
        customer_summary=(
            "There is no structured way for users to request admin approval for apps."
        ),
    )


def evaluate_app_password_addition_blocked(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    policies = list(evidence.get("ca_policies") or [])

    def _blocks_app_passwords(policy: dict[str, Any]) -> bool:
        if not ca.is_block_policy(policy):
            return False
        name = str(policy.get("displayName") or "").lower()
        return "app password" in name or "apppasswords" in name.replace(" ", "")

    enforced = [p for p in policies if ca.is_enabled(p) and _blocks_app_passwords(p)]
    evidence_out = {"enforced_policies": [p.get("displayName") for p in enforced]}
    if enforced:
        return Evaluation(
            status=FindingStatus.OK,
            summary="Conditional Access blocks application password addition.",
            evidence=evidence_out,
            customer_summary="Users cannot create legacy app passwords that bypass MFA.",
        )
    return Evaluation(
        status=FindingStatus.GAP,
        summary="No enforced policy blocking application password addition was found.",
        evidence=evidence_out,
        customer_summary=(
            "Users may still create app passwords that skip modern multi-factor checks."
        ),
    )


def evaluate_app_risky_delegated_consent(
    check: CheckDefinition,
    evidence: dict[str, Any],
) -> Evaluation:
    del check
    grants = _grants(evidence)
    risky: list[dict[str, str]] = []
    for grant in grants:
        scope = str(grant.get("scope") or "")
        scopes = {part.lower() for part in scope.split() if part}
        hit = sorted(scopes & _RISKY_SCOPES)
        if hit and str(grant.get("consentType") or "") == "AllPrincipals":
            risky.append(
                {
                    "client_id": str(grant.get("clientId") or "?"),
                    "scopes": " ".join(hit),
                }
            )
    evidence_out = {"risky_grant_count": len(risky), "sample": risky[:15]}
    if risky:
        return Evaluation(
            status=FindingStatus.GAP,
            summary=(f"Found {len(risky)} tenant-wide delegated grant(s) with high-impact scopes."),
            evidence=evidence_out,
            customer_summary=(
                "Some apps have broad mail, files, or directory permissions for everyone."
            ),
        )
    return Evaluation(
        status=FindingStatus.OK,
        summary="No high-impact tenant-wide delegated grants were found in the sample.",
        evidence=evidence_out,
        customer_summary="Delegated app permissions we reviewed do not show broad risky grants.",
    )

"""Preflight checks for live tenant connectivity."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from licenselens.auth import (
    GRAPH_SCOPE,
    REQUIRED_GRAPH_APP_PERMISSIONS,
    AuthContext,
    AuthMode,
)
from licenselens.collectors.skus import collect_subscribed_skus_live
from licenselens.errors import AuthError, GraphError
from licenselens.graph import GraphClient, fetch_organization_context

# Well-known Microsoft Graph resource app id (the appRoles owner).
GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"


class DoctorProfile(StrEnum):
    BASIC = "basic"
    FULL = "full"


@dataclass
class DoctorCheck:
    name: str
    ok: bool
    detail: str
    fix: str = ""
    optional: bool = False  # True = nice-to-have (e.g. MDE API); failure is ⚠, not ✗


@dataclass
class DoctorReport:
    mode: AuthMode
    profile: DoctorProfile = DoctorProfile.BASIC
    checks: list[DoctorCheck] = field(default_factory=list)
    tenant_id: str | None = None
    tenant_display_name: str | None = None
    sku_count: int = 0

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def ready(self) -> bool:
        """Identity-essential checks pass; optional probes may still warn."""
        return all(c.ok for c in self.checks if not c.optional)


def _read_granted_graph_app_permissions(
    client: GraphClient, client_id: str
) -> set[str]:
    """Return the app's granted Microsoft Graph application permission names.

    Resolves the app's service principal from its client id, reads its
    appRoleAssignments, and maps the assigned role ids onto the Microsoft
    Graph resource app's appRoles. Raises GraphError when the app id cannot
    be resolved or the read is denied.

    Note: the live read itself may require Directory.Read.All (reading
    servicePrincipals). If it is still denied, run_doctor degrades gracefully
    to the optional ⚠ row and never blocks report.ready.
    """
    if not client_id:
        raise GraphError("no app client id available for permission introspection")
    sp = client.get(f"/servicePrincipals(appId='{client_id}')")
    sp_id = sp.get("id")
    if not sp_id:
        raise GraphError(f"service principal for app id {client_id!r} not resolvable")
    assignments = client.get_list(f"/servicePrincipals/{sp_id}/appRoleAssignments")
    graph_sp = client.get(f"/servicePrincipals(appId='{GRAPH_RESOURCE_APP_ID}')")
    role_names = {
        str(role["id"]): str(role["value"])
        for role in graph_sp.get("appRoles") or []
        if isinstance(role, dict) and role.get("id") and role.get("value")
    }
    granted: set[str] = set()
    for assignment in assignments:
        role_id = str(assignment.get("appRoleId") or "")
        name = role_names.get(role_id)
        if name:
            granted.add(name)
    return granted


def run_doctor(
    auth: AuthContext,
    *,
    workspace_resource_id: str | None = None,
    profile: str | DoctorProfile = DoctorProfile.BASIC,
) -> DoctorReport:
    """Validate credentials and core Graph / optional Sentinel reads.

    profile="basic" runs core Graph checks; profile="full" also probes the
    Defender for Endpoint API and the optional Sentinel workspace.

    Always reports a graphPermissions row: granted application permissions vs
    REQUIRED_GRAPH_APP_PERMISSIONS (optional, never blocks report.ready).
    """
    try:
        profile_value = DoctorProfile(profile)
    except ValueError as exc:
        raise ValueError(f"Unknown doctor profile: {profile!r} (expected basic or full).") from exc
    report = DoctorReport(mode=auth.mode, profile=profile_value)

    if auth.mode == AuthMode.DRY_RUN:
        report.checks.append(
            DoctorCheck(
                name="mode",
                ok=True,
                detail=(
                    "Dry-run mode — no live tenant calls. "
                    f"Use --live --profile {profile_value.value} for production checks."
                ),
            )
        )
        report.checks.append(
            DoctorCheck(
                name="graphPermissions",
                ok=True,
                optional=True,
                detail=(
                    "Dry-run — skipped the live permission probe. "
                    f"Use --live to verify all {len(REQUIRED_GRAPH_APP_PERMISSIONS)} "
                    "required Graph application permissions are granted and consented."
                ),
            )
        )
        return report

    if auth.credential is None:
        report.checks.append(
            DoctorCheck(name="credential", ok=False, detail="No credential configured.")
        )
        return report

    report.checks.append(
        DoctorCheck(
            name="credential",
            ok=True,
            detail=f"Credential ready (mode={auth.mode.value}).",
        )
    )

    try:
        token = auth.credential.get_token(GRAPH_SCOPE)
        report.checks.append(
            DoctorCheck(
                name="token",
                ok=bool(token and token.token),
                detail="Acquired Microsoft Graph token."
                if token and token.token
                else "Token empty.",
            )
        )
    except Exception as exc:  # noqa: BLE001
        report.checks.append(
            DoctorCheck(name="token", ok=False, detail=f"Token acquisition failed: {exc}")
        )
        return report

    try:
        with GraphClient(auth) as client:
            tid, name = fetch_organization_context(client)
            report.tenant_id = tid or auth.tenant_id
            report.tenant_display_name = name
            if tid or name:
                report.checks.append(
                    DoctorCheck(
                        name="organization",
                        ok=True,
                        detail=f"Organization read ok ({name or tid}).",
                    )
                )
            else:
                report.checks.append(
                    DoctorCheck(
                        name="organization",
                        ok=False,
                        detail=(
                            "Could not read /organization. "
                            "Grant Organization.Read.All (application) with admin consent."
                        ),
                        fix="Grant Organization.Read.All (application) with admin consent.",
                    )
                )

            try:
                skus = collect_subscribed_skus_live(client)
                report.sku_count = len(skus)
                report.checks.append(
                    DoctorCheck(
                        name="subscribedSkus",
                        ok=True,
                        detail=f"Read {len(skus)} subscribed SKU(s).",
                    )
                )
            except GraphError as exc:
                report.checks.append(
                    DoctorCheck(
                        name="subscribedSkus",
                        ok=False,
                        detail=str(exc),
                        fix="Grant Organization.Read.All so licenses can be read.",
                    )
                )

            try:
                from licenselens.collectors.conditional_access import collect_ca_policies

                policies = collect_ca_policies(client)
                report.checks.append(
                    DoctorCheck(
                        name="conditionalAccess",
                        ok=True,
                        detail=f"Read {len(policies)} Conditional Access policy(ies).",
                    )
                )
            except GraphError as exc:
                report.checks.append(
                    DoctorCheck(
                        name="conditionalAccess",
                        ok=False,
                        detail=str(exc),
                        fix="Grant Policy.Read.All (or the CA read scope) with admin consent.",
                    )
                )

            try:
                from licenselens.collectors.privileged_roles import collect_role_assignments

                roles = collect_role_assignments(client)
                report.checks.append(
                    DoctorCheck(
                        name="roleAssignments",
                        ok=True,
                        detail=f"Read {len(roles)} directory role assignment(s).",
                    )
                )
            except GraphError as exc:
                report.checks.append(
                    DoctorCheck(
                        name="roleAssignments",
                        ok=False,
                        detail=str(exc),
                        fix="Grant RoleManagement.Read.Directory to read privileged roles.",
                    )
                )

            try:
                from licenselens.collectors.secure_score import collect_latest_secure_score

                score = collect_latest_secure_score(client)
                n = len((score or {}).get("controlScores") or [])
                report.checks.append(
                    DoctorCheck(
                        name="secureScore",
                        ok=score is not None,
                        detail=(
                            f"Secure Score read ok ({n} control scores)."
                            if score
                            else "No Secure Score snapshot returned."
                        ),
                        optional=True,
                        fix="Grant SecurityEvents.Read.All if you use --allow-email-proxy.",
                    )
                )
            except GraphError as exc:
                report.checks.append(
                    DoctorCheck(
                        name="secureScore",
                        ok=False,
                        detail=str(exc),
                        optional=True,
                        fix="Grant the Secure Score read permission with admin consent.",
                    )
                )

            # Email policy config has no Graph read path (PowerShell-only).
            report.checks.append(
                DoctorCheck(
                    name="emailProtection",
                    ok=False,
                    optional=True,
                    detail=(
                        "Email policy config (Safe Links / Safe Attachments / "
                        "preset Standard·Strict) is not readable via Graph."
                    ),
                    fix=(
                        "Verify in Defender portal → Preset security policies, "
                        "or Exchange Online PowerShell (Get-ATPProtectionPolicyRule). "
                        "Optional: --allow-email-proxy for a labeled Secure Score path."
                    ),
                )
            )

            # Enforcement/reporting: are the required Graph application
            # permissions actually granted on this app? Optional — never
            # blocks report.ready (the per-collector ✗ rows gate that).
            try:
                granted = _read_granted_graph_app_permissions(
                    client, auth.client_id or ""
                )
                missing = [p for p in REQUIRED_GRAPH_APP_PERMISSIONS if p not in granted]
                if missing:
                    report.checks.append(
                        DoctorCheck(
                            name="graphPermissions",
                            ok=False,
                            optional=True,
                            detail=f"Missing application permission(s): {', '.join(missing)}.",
                            fix=f"Grant {', '.join(missing)} and re-consent.",
                        )
                    )
                else:
                    report.checks.append(
                        DoctorCheck(
                            name="graphPermissions",
                            ok=True,
                            optional=True,
                            detail=(
                                "All required Graph application permissions granted."
                            ),
                        )
                    )
            except GraphError as exc:
                report.checks.append(
                    DoctorCheck(
                        name="graphPermissions",
                        ok=False,
                        optional=True,
                        detail=f"cannot verify granted permissions — {exc}",
                        fix=(
                            "Verify the required application permissions in Entra "
                            "admin center and re-consent (docs/app-registration.md)."
                        ),
                    )
                )
    except (AuthError, GraphError) as exc:
        report.checks.append(
            DoctorCheck(
                name="graph",
                ok=False,
                detail=str(exc),
                fix="Confirm credentials and that the app has admin consent.",
            )
        )

    # Optional Defender for Endpoint API (separate resource) — full profile only
    if (
        profile_value == DoctorProfile.FULL
        and auth.mode != AuthMode.DRY_RUN
        and auth.credential is not None
    ):
        try:
            from licenselens.collectors.mde import collect_mde_machine_summary

            mde = collect_mde_machine_summary(auth)
            report.checks.append(
                DoctorCheck(
                    name="defenderEndpoint",
                    ok=True,
                    detail=(
                        f"MDE API ok — onboarded machines signal: "
                        f"{mde.get('onboarded_machines')} ({mde.get('count_method')})."
                    ),
                )
            )
        except (AuthError, GraphError) as exc:
            report.checks.append(
                DoctorCheck(
                    name="defenderEndpoint",
                    ok=False,
                    detail=str(exc),
                    optional=True,
                    fix="Endpoint pack is optional — "
                    "identity scanning still works without MDE API.",
                )
            )

        # Optional Sentinel workspace (ARM)
        if workspace_resource_id:
            try:
                from licenselens.collectors.sentinel import collect_sentinel_bundle

                bundle = collect_sentinel_bundle(auth, workspace_resource_id)
                rules = bundle.get("sentinel_rules") or {}
                ueba = bundle.get("sentinel_ueba") or {}
                report.checks.append(
                    DoctorCheck(
                        name="sentinelWorkspace",
                        ok=True,
                        detail=(
                            f"Sentinel workspace ok — rules total="
                            f"{rules.get('total_rules')}, enabled_scheduled="
                            f"{rules.get('enabled_scheduled_or_nrt')}, "
                            f"ueba={ueba.get('ueba_enabled')}."
                        ),
                    )
                )
            except (AuthError, GraphError) as exc:
                report.checks.append(
                    DoctorCheck(
                        name="sentinelWorkspace",
                        ok=False,
                        detail=str(exc),
                        optional=True,
                        fix="Sentinel is optional — the scan runs without it.",
                    )
                )
        else:
            report.checks.append(
                DoctorCheck(
                    name="sentinelWorkspace",
                    ok=True,
                    detail=("Skipped (pass --workspace-resource-id to probe Sentinel)."),
                )
            )

    return report

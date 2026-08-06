"""Preflight checks for live tenant connectivity."""

from __future__ import annotations

from dataclasses import dataclass, field

from licenselens.auth import GRAPH_SCOPE, AuthContext, AuthMode
from licenselens.collectors.skus import collect_subscribed_skus_live
from licenselens.errors import AuthError, GraphError
from licenselens.graph import GraphClient, fetch_organization_context


@dataclass
class DoctorCheck:
    name: str
    ok: bool
    detail: str


@dataclass
class DoctorReport:
    mode: AuthMode
    checks: list[DoctorCheck] = field(default_factory=list)
    tenant_id: str | None = None
    tenant_display_name: str | None = None
    sku_count: int = 0

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


def run_doctor(auth: AuthContext) -> DoctorReport:
    """Validate credentials and core Graph reads used by Session A."""
    report = DoctorReport(mode=auth.mode)

    if auth.mode == AuthMode.DRY_RUN:
        report.checks.append(
            DoctorCheck(
                name="mode",
                ok=True,
                detail="Dry-run mode — no live tenant calls. Use --live for production checks.",
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
                    )
                )
    except (AuthError, GraphError) as exc:
        report.checks.append(
            DoctorCheck(name="graph", ok=False, detail=str(exc))
        )

    return report

# MSP Friday ritual

Vendor-neutral multi-tenant workflow. No product branding in reports.

## App-only auth (once per customer)

1. Entra ID → App registrations → New registration (single tenant or multi).
2. Certificates & secrets → client secret (or cert).
3. API permissions (application) + **admin consent**:
   - `Organization.Read.All`
   - `Policy.Read.All`
   - `RoleManagement.Read.Directory`
   - `User.Read.All` (directory lookups)
   - `AuditLog.Read.All` (sign-in activity)
   - `SecurityEvents.Read.All` (optional Secure Score / proxy packs)
   - MDE API permission if using endpoint pack live
4. Store `tenant_id`, `client_id`, secret in a secrets manager — not in git.

See also [app-registration.md](app-registration.md) and [permissions.md](permissions.md).

## tenants.yaml

```yaml
defaults:
  auth: client_secret
  # packs default to identity + endpoint when omitted

tenants:
  - slug: contoso
    tenant_id: "..."
  - slug: fabrikam
    tenant_id: "..."
    workspace_resource_id: "/subscriptions/.../workspaces/..."
```

Full example: [examples/tenants.yaml](https://github.com/d4rk-pri0r/licenselens/blob/main/examples/tenants.yaml).

Email is **off by default** (no Graph API for MDO policy config). Only set `allow_email_proxy: true` when the customer accepts a labeled Secure Score degraded path.

## Friday batch

```bash
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...

licenselens batch tenants.yaml -o reports/$(date +%Y-%m-%d) --live
open reports/$(date +%Y-%m-%d)/index.md
```

Index sorts **EXPOSED first**, then lowest % realized. Open each tenant HTML for the same top-card contract as a single scan.

## Monthly diff

```bash
licenselens diff reports/2026-07-01/contoso/security-license-lens-report.json \
                 reports/2026-08-01/contoso/security-license-lens-report.json \
                 -o reports/contoso-diff.md
```

## Notes

- Read-only. Advisory only. Confirm in the portal before change tickets.
- Starter packs (Sentinel/Purview/MDI) stay out of the default top card unless you pass `--pack starter`.

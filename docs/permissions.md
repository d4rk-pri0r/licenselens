# Permissions

LicenseLens is designed for **read-only** access.

## Microsoft Graph (application permissions) — planned v0.1

| Permission | Purpose |
|------------|---------|
| `Organization.Read.All` | Subscribed SKUs / service plans |
| `Directory.Read.All` | Directory roles, basic identity inventory |
| `RoleManagement.Read.Directory` | Role assignments / PIM surfaces |
| `Policy.Read.All` | Conditional Access policies |
| `IdentityRiskyUser.Read.All` | Identity Protection risky users |
| `IdentityRiskEvent.Read.All` | Identity Protection risk events |
| `AuditLog.Read.All` | Sign-in logs (dormant privileged, CA evidence) |
| `User.Read.All` | User enablement / UPN context |
| `Application.Read.All` | App inventory where needed |

Workload-specific APIs (MDE, MDI, Sentinel, Purview) will document additional roles as collectors land.

## Azure RBAC (Sentinel checks)

- **Log Analytics Reader** (or equivalent) on target workspaces
- **Microsoft Sentinel Reader** where required for analytics rule inventory

## Least privilege

Prefer a dedicated app registration with **no write permissions**. Do not grant `*.ReadWrite.*` for LicenseLens.

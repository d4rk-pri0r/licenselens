# Permissions

Security License Lens is designed for **read-only** access.

## Microsoft Graph (application permissions) — identity pack (v0.1)

| Permission | Purpose |
|------------|---------|
| `Organization.Read.All` | Tenant profile + subscribed SKUs |
| `Directory.Read.All` | Directory object lookup for privileged principals |
| `RoleManagement.Read.Directory` | Role assignments + PIM eligibility (`id-pim-unused`, `id-dormant-privileged`) |
| `Policy.Read.All` | Conditional Access (`id-ca-priv-gaps`, `id-idprotect-off`) |
| `AuditLog.Read.All` | Sign-in logs (`id-dormant-privileged`) |
| `User.Read.All` | Optional user detail (often covered by Directory.Read.All) |
| `SecurityEvents.Read.All` | Secure Score (MDO / MDI proxy signals) |

Grant **application** permissions and **admin consent**.

## Defender for Endpoint API (separate resource)

| Permission | Application | Purpose |
|------------|-------------|---------|
| `Machine.Read.All` | WindowsDefenderATP / Microsoft Defender for Endpoint | Onboarded device inventory (`mde-onboard-gap`) |

In Entra app registration → **API permissions** → **APIs my organization uses** → search **WindowsDefenderATP** or **Microsoft Defender for Endpoint** → Application permission `Machine.Read.All` → admin consent.

Token audience: `https://api.securitycenter.microsoft.com`.

## Still upcoming

Sentinel (Azure RBAC) and Purview DLP collectors document additional roles when they ship.

## Azure RBAC (Sentinel checks — future)

- **Log Analytics Reader** (or equivalent) on target workspaces
- **Microsoft Sentinel Reader** where required for analytics rule inventory

## Least privilege

Prefer a dedicated app registration with **no write permissions**. Do not grant `*.ReadWrite.*` for Security License Lens.

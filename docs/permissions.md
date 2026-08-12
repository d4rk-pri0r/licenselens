# Permissions

Security License Lens is designed for **read-only** access.

## Microsoft Graph (application permissions)

| Permission | Purpose |
|------------|---------|
| `Organization.Read.All` | Tenant profile + subscribed SKUs |
| `Directory.Read.All` | Directory object lookup for privileged principals |
| `RoleManagement.Read.Directory` | Role assignments + PIM eligibility |
| `Policy.Read.All` | Conditional Access |
| `AuditLog.Read.All` | Sign-in logs (dormant privileged) |
| `SecurityEvents.Read.All` | Secure Score (MDO / MDI / DLP proxy signals) |
| `AccessReview.Read.All` | Access review definitions |

Grant **application** permissions and **admin consent**.

## Defender for Endpoint API (separate resource)

| Permission | Application | Purpose |
|------------|-------------|---------|
| `Machine.Read.All` | WindowsDefenderATP / Microsoft Defender for Endpoint | Onboarded device inventory |

Token audience: `https://api.securitycenter.microsoft.com`.

## Microsoft Sentinel (Azure RBAC)

Sentinel checks require a workspace binding:

```bash
--workspace-resource-id /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}
```

Or:

```bash
--subscription-id ... --resource-group ... --workspace-name ...
```

| Role on workspace (recommended) | Purpose |
|----------------------------------|---------|
| **Microsoft Sentinel Reader** | Analytics rules + settings |
| Log Analytics Reader | Often insufficient alone for SecurityInsights APIs |

The app’s service principal (or signed-in user) must hold the role on the workspace (or parent RG/subscription).

Token audience: `https://management.azure.com`.

## Purview DLP

v0.2 uses **Secure Score** DLP/information-protection controls as a proxy (`SecurityEvents.Read.All`). Direct Purview policy APIs are attempted best-effort and may not be available to app-only auth.

## Least privilege

Prefer a dedicated app registration with **no write permissions**. Do not grant `*.ReadWrite.*` for Security License Lens.

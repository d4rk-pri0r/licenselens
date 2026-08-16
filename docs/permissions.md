# Permissions

Security License Lens is designed for **read-only** access.

## Microsoft Graph (application permissions)

| Permission | Purpose |
|------------|---------|
| `Organization.Read.All` | Tenant profile + subscribed SKUs |
| `Directory.Read.All` | Directory object lookup for privileged principals |
| `Domain.Read.All` | Verified domain password-validity settings |
| `User.Read.All` | Guest user inventory (least privilege vs full directory dumps) |
| `RoleManagement.Read.Directory` | Role assignments + PIM eligibility and policy rules |
| `Policy.Read.All` | Conditional Access, named locations, auth methods, cross-tenant |
| `Application.Read.All` | App registrations and service principals |
| `DelegatedPermissionGrant.Read.All` | OAuth2 delegated permission grants |
| `AuditLog.Read.All` | Sign-in logs (dormant privileged) |
| `SecurityEvents.Read.All` | Secure Score (MDO / MDI / DLP proxy signals) |
| `SecurityIncident.Read.All` | Defender XDR incidents (capability operation signal) |
| `SecurityAlert.Read.All` | Defender XDR alerts_v2 (capability operation signal) |
| `AccessReview.Read.All` | Access review definitions |
| `EntitlementManagement.Read.All` | Entitlement Management access packages |
| `IdentityRiskyServicePrincipal.Read.All` | Risky workload-identity (service principal) detection |
| `DeviceManagementApps.Read.All` | Intune MAM app-protection policies |
| `DeviceManagementConfiguration.Read.All` | Intune compliance/configuration/endpoint-security policies |
| `DeviceManagementManagedDevices.Read.All` | Intune managed device inventory (bounded) |
| `DlpPolicy.Read.All` | Purview DLP policies + apps (direct, `/security/dataLossPreventionPolicies`) |
| `eDiscovery.Read.All` | Premium eDiscovery cases (direct, `/security/cases/ediscoveryCases`) |

Grant **application** permissions and **admin consent**.

Delegated equivalents (device-code / interactive) are declared per operation in
`src/licenselens/graph_ops.py` and are always read-only (`*.Read.*` / `*.Read.All`).

National clouds: Graph/ARM/MDE base URLs are modeled in
`src/licenselens/cloud_endpoints.py` (`public`, `us_gov`, `china`) but there is
no CLI cloud flag — national-cloud selection is modeled in code, not user-selectable.
Collectors mark unsupported cloud+operation pairs instead of calling the wrong root.

## Defender for Endpoint API (separate resource)

| Permission | Application | Purpose |
|------------|-------------|---------|
| `Machine.Read.All` | WindowsDefenderATP / Microsoft Defender for Endpoint | Onboarded device inventory + healthStatus summary |

Token audience (public): `https://api.securitycenter.microsoft.com`.
US Government: `https://api-gov.securitycenter.microsoft.us`.
China cloud MDE is treated as unsupported.

## Microsoft Sentinel / selective Azure (Azure RBAC)

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

Optional selective Azure (not generic CSPM):

| Scope | Role / access | Purpose |
|-------|---------------|---------|
| Subscription | **Security Reader** (or equivalent read on `Microsoft.Security/pricings`) | Defender for Cloud plan pricing only |

Token audience (public): `https://management.azure.com`.
US Government: `https://management.usgovcloudapi.net`.

LicenseLens does **not** enumerate VMs, storage, SQL, or network resources for
benchmark-style CSPM.

## Purview DLP, eDiscovery, and Insider Risk Management

Purview DLP reads **direct Graph policy evidence** first
(`/security/dataLossPreventionPolicies` + `/security/dataLossPreventionApps`,
`DlpPolicy.Read.All`) and falls back to **Secure Score** DLP/information-protection
controls (`SecurityEvents.Read.All`) when the direct read is unavailable.

Premium eDiscovery cases are read directly from Graph v1.0
(`/security/cases/ediscoveryCases`, `eDiscovery.Read.All`). App-only access must
additionally be added to the eDiscovery Administrator role group via
`Add-eDiscoveryCaseAdmin` (see docs/app-registration.md); otherwise the case
list can come back empty even when cases exist.

Insider Risk Management policies are read from the Graph **beta** endpoint
(`/security/insiderRiskManagement/policies`). This API uses the delegated scope
`InsiderRiskPolicy.Read.All` and requires the signed-in user to hold an Insider
Risk Management role group membership; it is not part of the pre-verified
application permission list above.

PowerShell bridge adapters also collect readable Purview surfaces when modules
are present.

## Power BI / Fabric admin REST (separate resource)

Premium capacity governance reads the Power BI admin REST API
(`admin/capacities` + `admin/tenantsettings`).

| Permission | Purpose |
|------------|---------|
| `Tenant.Read.All` | Premium/Fabric capacity + admin list and tenant settings |

Token audience: `https://analysis.windows.net/powerbi/api/.default` (a separate
resource from Microsoft Graph). Admin endpoints require **app-only** auth or a
signed-in **Fabric administrator**.

## Exchange Online / Security & Compliance (PowerShell bridge)

MDO email policy config (Safe Links, Safe Attachments, preset policies, anti-phish, etc.) is **not** available via Microsoft Graph. LicenseLens collects it through the allowlisted PowerShell bridge (`powershell/LicenseLens.Collectors/adapters/`) using official modules only:

| Module / session | Purpose |
|------------------|---------|
| `ExchangeOnlineManagement` + EXO session | Org/mailbox audit, remote domains, transport rules, SMTP AUTH, sharing, accepted domains, DKIM, malware/phish, Safe Links/Attachments, preset security, quarantine |
| `ExchangeOnlineManagement` IPPS / SCC session | DLP policies/rules, sensitivity labels/label policies, audit log config |

Required admin roles (typical): **Global Reader** or **Security Reader** plus Exchange/View-Only organization management as needed for the surfaces above. The bridge never runs `Set-`/`New-`/`Remove-` remediation cmdlets.

When direct EXO threat-policy reads succeed, they **supersede** the Secure Score email proxy. `--allow-email-proxy` remains an opt-in degraded fallback only.

## Teams / SharePoint Online / OneDrive (PowerShell bridge)

Collaboration policy config (sharing scope, default links, expiration, domain allowlists, Teams meeting/lobby/recording, external access, unmanaged users, email integration, and app permission policies) is collected through the allowlisted PowerShell bridge using official modules only:

| Module / session | Purpose |
|------------------|---------|
| `Microsoft.Online.SharePoint.PowerShell` | `Get-SPOTenant` sharing capability, default links, anyone-link expiration/permissions, verification-code reauth, and domain allowlist |
| `MicrosoftTeams` | Meeting/lobby/recording and live-event policies, federation/external access, unmanaged-user access, client email integration, and app permission policies |

Required admin roles (typical): **Global Reader** or **Teams Administrator** / **SharePoint Administrator** for the surfaces above. The bridge never runs `Set-`/`New-`/`Remove-`/`Grant-` remediation cmdlets. Teams unmanaged-user and email-integration surfaces are not available on GCC/GCC High/DoD tenants; those checks report not-applicable rather than a false gap.

## Least privilege

Prefer a dedicated app registration with **no write permissions**. Do not grant `*.ReadWrite.*` for Security License Lens.

The authoritative per-operation matrix (path, application + delegated permissions, cloud support, preview flag) lives in `src/licenselens/graph_ops.py`. Beta endpoints are blocked unless a profile explicitly opts into preview.

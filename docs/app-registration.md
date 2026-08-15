# App registration (live scans)

Security License Lens is **read-only**. Create a dedicated Entra ID app
registration for assessments. Live auth modes implemented today:

| Mode | CLI value | When to use |
|------|-----------|-------------|
| Device code | `--auth device` | Interactive consultant laptop |
| Client secret | `--auth client_secret` | Automation, MSP runbooks, CI |
| Azure CLI | `--auth azure_cli` | You already ran `az login` |

## 1. Register the application

1. Entra admin center → **App registrations** → **New registration**
2. Name: `Security License Lens` (or your firm’s name)
3. Supported account types: single tenant (typical)
4. No redirect URI required for client-credentials; for device code with your
   own app, enable public client flows as needed

## 2. Auth modes

### Device code (`device`)

Requires a **tenant id** (`--tenant-id` or `AZURE_TENANT_ID`).

Optional: pass your own app’s **client id** (`--client-id` or
`AZURE_CLIENT_ID`). If omitted, LicenseLens falls back to the Microsoft Graph
PowerShell public client `14d82eec-204b-4c2f-b7e8-296a70dab67e`. Prefer
registering your own app for production assessments so consent and audit stay
under your control.

```bash
licenselens doctor --live --auth device \
  --tenant-id "$AZURE_TENANT_ID" \
  --client-id "$AZURE_CLIENT_ID"
```

### Client secret (`client_secret`)

App-only credentials via environment variables (preferred) or CLI flags:

```bash
export AZURE_TENANT_ID="<tenant-guid>"
export AZURE_CLIENT_ID="<app-id>"
export AZURE_CLIENT_SECRET="<secret>"
licenselens doctor --live --auth client_secret
licenselens scan --live --auth client_secret -o reports
```

Store the secret in a secret manager. Never commit secrets or paste them into
tickets. `--client-secret` is accepted but visible in process lists; prefer the
env var.

### Azure CLI (`azure_cli`)

Sign in with the Azure CLI, then point LicenseLens at that session:

```bash
az login
licenselens doctor --live --auth azure_cli
licenselens scan --live --auth azure_cli -o reports
```

Uses `AzureCliCredential` from azure-identity. No client secret is required on
the LicenseLens command line when the CLI session already has access.

## 3. API permissions (application, admin consent)

See the full matrix (including MDE, Sentinel RBAC, and PowerShell roles) in
[permissions.md](permissions.md).

**Microsoft Graph (application)** — the 15 permissions LicenseLens expects
(`REQUIRED_GRAPH_APP_PERMISSIONS`):

- `AccessReview.Read.All`
- `Application.Read.All`
- `AuditLog.Read.All`
- `DelegatedPermissionGrant.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `Directory.Read.All`
- `Domain.Read.All`
- `Organization.Read.All`
- `Policy.Read.All`
- `RoleManagement.Read.Directory`
- `SecurityAlert.Read.All`
- `SecurityEvents.Read.All`
- `SecurityIncident.Read.All`
- `User.Read.All`

**Microsoft Defender for Endpoint** (optional, for `mde-onboard-gap` and related
endpoint probes):

- API: WindowsDefenderATP / Microsoft Defender for Endpoint
- Application permission: `Machine.Read.All`

**Microsoft Sentinel** (optional, for Sentinel checks):

- Assign the app’s service principal **Microsoft Sentinel Reader** on the target
  Log Analytics workspace (or parent scope)
- Pass `--workspace-resource-id` (full ARM ID) on `scan` / `doctor`, or set
  `SENTINEL_WORKSPACE_RESOURCE_ID` (or subscription + resource group + workspace
  name env vars — see [CLI reference](cli.md))

Grant **admin consent** after adding Graph/MDE permissions.

> If Graph returns 403, re-check consent and re-run `licenselens doctor --live`.

## 4. Client secret lifecycle

1. App registration → **Client secrets** → **New client secret**
2. Store in a secret manager; set `AZURE_CLIENT_SECRET`
3. Never commit secrets or paste them into tickets

## 5. Verify

```bash
# App-only
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
licenselens doctor --live --auth client_secret

# Interactive device code (your app id recommended)
licenselens doctor --live --auth device \
  --tenant-id "$AZURE_TENANT_ID" \
  --client-id "$AZURE_CLIENT_ID"

# Existing az login session
licenselens doctor --live --auth azure_cli
```

Expected: token ok, organization ok, subscribedSkus count > 0.

## 6. Scan

```bash
licenselens scan --live --auth client_secret -o reports
# or: --auth device / --auth azure_cli
open reports/security-license-lens-report.html
```

Reports write flat into `-o` (default `reports`) as
`security-license-lens-report.{html,json,md}`. See [Report](report.md).

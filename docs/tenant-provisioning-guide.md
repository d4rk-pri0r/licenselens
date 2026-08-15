# Tenant provisioning runbook (live validation)

This is the step-by-step runbook to provision a synthetic lab tenant and exercise
the full live-lab matrix for the expanded assessment. It is self-contained: one
person with Global Admin rights can complete it end to end without reading any
other doc.

Security License Lens is **read-only**. Nothing here changes your tenant. The app
registration already exists, we confirm its read permissions, grab a client
secret, and point the tool at the lab.

> **Placeholders only.** Every identifier below uses `<PLACEHOLDER>` values. The
> real tenant/app/subscription identifiers live only in `.env` (gitignored) and
> are never committed, pasted into chat, or written into evidence. See
> `catalog/lab/live-lab-matrix.yaml` for the machine-readable matrix and
> `scripts/lab_runner.py` for the redacted runner.

## What you end up with

- The borrowed app registration has the Graph read permissions, Defender for
  Endpoint read access, and the Azure RBAC role bindings for Sentinel, with
  admin consent granted.
- The official PowerShell modules for Exchange/SCC, SharePoint, Teams, Power
  Platform, and Power BI are installed for the bridge collectors.
- `.env` holds the tenant, app, secret, and Sentinel workspace binding locally.
- The lab tenant is seeded with the intentionally weak settings the checks are
  meant to surface, plus clean controls that must report `ok`.
- `licenselens doctor` confirms every preflight check passes before a live scan.

## Prerequisites

- Global Admin (or equivalent) rights in the lab tenant `<TENANT_ID>`.
- Access to the borrowed app registration `<APP_ID>`.
- A local checkout of the repo with the CLI installed (`uv run licenselens`).
- PowerShell 7 (`pwsh`) plus the official modules below, if the PowerShell-bridge
  families are in scope.

## Step 1. Confirm the borrowed app registration permissions

Sign in to the Entra admin center in the lab tenant and open **App
registrations**, then search for the borrowed app id `<APP_ID>`.

### 1a. Graph application permissions (read)

Under **API permissions → Microsoft Graph → Application permissions**, confirm
all of the following are present. Add any that are missing:

- `Organization.Read.All`
- `Directory.Read.All`
- `Domain.Read.All`
- `User.Read.All`
- `RoleManagement.Read.Directory`
- `Policy.Read.All`
- `Application.Read.All`
- `DelegatedPermissionGrant.Read.All`
- `AuditLog.Read.All`
- `SecurityEvents.Read.All`
- `SecurityIncident.Read.All`
- `SecurityAlert.Read.All`
- `AccessReview.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`

These are **application** permissions, not delegated, and they are read-only.

### 1b. Defender for Endpoint permission

Add a second API: **Microsoft Defender for Endpoint** (WindowsDefenderATP).

- Application permission: `Machine.Read.All`
- Token audience for this resource: `https://api.securitycenter.microsoft.com`

### 1c. Sentinel workspace read role

The app's service principal needs **Microsoft Sentinel Reader** on the lab
workspace so the Sentinel checks can read analytics rules and settings. In the
Azure portal, open the `<RESOURCE_GROUP>` resource group, then the
`<WORKSPACE_NAME>` Log Analytics workspace, and go to **Access control (IAM)**.

- Add role assignment: **Microsoft Sentinel Reader**
- Assign to: the service principal for app `<APP_ID>`

For the selective Defender for Cloud check (`az-defender-plan-enabled`), grant
**Security Reader** on the `<SUBSCRIPTION_ID>` subscription.

### 1d. PowerShell bridge modules (official, read-only)

Install the official modules the bridge collectors use. The bridge only runs
checked-in adapters and never runs `Set-`/`New-`/`Remove-` cmdlets.

- `ExchangeOnlineManagement` (EXO + SCC/IPPS sessions)
- `Microsoft.Online.SharePoint.PowerShell`
- `MicrosoftTeams`
- `Microsoft.PowerApps.Administration.PowerShell` (Power Platform)
- `MicrosoftPowerBIMgmt` (Power BI)

### 1e. Grant admin consent

After the Graph and Defender for Endpoint permissions are in place, click
**Grant admin consent** on the Graph API and again for the Defender for Endpoint
API. Until consent is granted, Graph calls return 403.

## Step 2. Create the client secret and set `.env`

1. In the app registration, open **Certificates & secrets → New client secret**.
2. Set a short expiry that covers the validation window and record the **Value**
   when it appears. It is only shown once.
3. From the repo root, copy the template and fill it in:

```bash
cp .env.example .env
```

Then edit `.env` so it contains:

```bash
AZURE_TENANT_ID=<TENANT_ID>
AZURE_CLIENT_ID=<APP_ID>
AZURE_CLIENT_SECRET=<secret>
AZURE_SUBSCRIPTION_ID=<SUBSCRIPTION_ID>
SENTINEL_RESOURCE_GROUP=<RESOURCE_GROUP>
SENTINEL_WORKSPACE_NAME=<WORKSPACE_NAME>
```

The last three lines bind the Sentinel workspace; they map to the
`--subscription-id`, `--resource-group`, and `--workspace-name` flags.

**Secrets go only in `.env`.** That file is gitignored. Never paste the real
client secret into chat, a ticket, a commit, or this guide. Use `<secret>` as a
placeholder everywhere except the actual `.env` file.

## Step 3. Seed the tenant

Follow `docs/lab-seed-checklist.md` to seed the intentionally weak settings and
their clean-control counterparts across the seven families:

1. Identity (Graph)
2. Email / Security Suite (PowerShell bridge)
3. Collaboration (PowerShell bridge)
4. Power Platform + Power BI (PowerShell bridge)
5. Endpoint / XDR (Graph + MDE)
6. Purview (PowerShell bridge)
7. Sentinel + selective Azure (ARM)

Prefer under-fire to over-fire on EXPOSED. Every family must have at least one
fail case (→ `gap`/`partial`) and one pass case (→ `ok`).

## Step 4. Verify

Run the doctor preflight against the live tenant:

```bash
uv run licenselens doctor --live --auth client_secret --profile full
```

`--profile full` probes Graph, the Defender for Endpoint API, the Sentinel
workspace, and the PowerShell bridge modules. Expected: token ok, organization
ok, subscribed SKUs present, and no permission errors. If Graph returns 403,
re-check admin consent and re-run.

Then a live scan:

```bash
uv run licenselens scan --live --auth client_secret -o reports-live
```

**Live reports contain tenant data.** Always write them under `reports-live/`,
not the demo `reports/` folder, and do not commit them. Treat every live report
as sensitive until you have scrubbed it.

### Matrix dry-run (no live tenant)

On a host without a Microsoft tenant, validate the matrix and produce redacted
receipts against fake backends only:

```bash
uv run python scripts/lab_runner.py validate
uv run python scripts/lab_runner.py receipt \
  --out .omo/evidence/maturity-and-check-expansion/
```

The receipts state clearly that no real tenant was touched.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings) |
| 1 | Completed with gap or partial findings |
| 2 | Auth / configuration / API error |

A seeded tenant should produce exit 1 (gap findings) for the scan. Exit 2 means
something is wrong with auth, consent, or the `.env` binding. Fix that before
continuing.

### Negative cases (must NOT pass)

- **Permission denied** — remove one read permission and re-run: that family
  reports `error`/`skipped`, never `ok`.
- **Unsupported cloud** — bind a GCC/GCC High/DoD/China surface: `skipped`/
  `not_applicable`, never `ok`.
- **Empty tenant** — scan a tenant with no users/devices/policies: bounded empty
  states, never a false pass.
- **Large tenant** — scan a large tenant: paginated/truncated inventory reports
  `partial`, confidence lowered.

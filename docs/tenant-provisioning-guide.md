# Tenant provisioning runbook (live validation)

This is the step-by-step runbook to reuse the borrowed app registration and seed
the demo tenant for live validation. It is self-contained: one person with Global
Admin rights can complete it end to end without reading any other doc.

Security License Lens is **read-only**. Nothing here changes your tenant. The app
registration already exists, we just confirm its read permissions, grab a client
secret, and point the tool at the lab.

## What you end up with

- The borrowed app registration has the 7 Graph read permissions plus Defender
  for Endpoint and Sentinel read access, with admin consent granted.
- `.env` holds the tenant, app, secret, and Sentinel workspace binding locally.
- The lab tenant is seeded with the intentionally weak settings the live checks
  are meant to surface.
- `licenselens doctor` confirms every preflight check passes before a live scan.

## Prerequisites

- Global Admin (or equivalent) rights in the borrowed tenant
  `841dd580-a74b-4133-ac70-398fd3fc28bb`.
- Access to the borrowed app registration
  `abeafa89-bfe1-4885-9cf2-a18510fe62ff`.
- A local checkout of the repo with the CLI installed (`uv run licenselens`).

## Step 1. Confirm the borrowed app registration permissions

Sign in to the Entra admin center in the borrowed tenant and open **App
registrations**, then search for the borrowed app id
`abeafa89-bfe1-4885-9cf2-a18510fe62ff`.

### 1a. Graph application permissions (read)

Under **API permissions → Microsoft Graph → Application permissions**, confirm all
seven are present. Add any that are missing:

- `Organization.Read.All`
- `Directory.Read.All`
- `Policy.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`
- `SecurityEvents.Read.All`
- `AccessReview.Read.All`

These are **application** permissions, not delegated, and they are read-only.

### 1b. Defender for Endpoint permission

Add a second API: **Microsoft Defender for Endpoint** (WindowsDefenderATP).

- Application permission: `Machine.Read.All`
- Token audience for this resource: `https://api.securitycenter.microsoft.com`

### 1c. Sentinel workspace read role

The app's service principal needs **Microsoft Sentinel Reader** on the lab
workspace so the Sentinel checks can read analytics rules and settings. In the
Azure portal, open the `darkpriorlabs` resource group, then the `dp-labs-dev`
Log Analytics workspace, and go to **Access control (IAM)**.

- Add role assignment: **Microsoft Sentinel Reader**
- Assign to: the service principal for app `abeafa89-bfe1-4885-9cf2-a18510fe62ff`

Do **not** remove the app's existing Sentinel write/hydration roles. Those are
part of the lab setup and are needed by other tooling. We are only adding read
access on top of them.

### 1d. Grant admin consent

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
AZURE_TENANT_ID=841dd580-a74b-4133-ac70-398fd3fc28bb
AZURE_CLIENT_ID=abeafa89-bfe1-4885-9cf2-a18510fe62ff
AZURE_CLIENT_SECRET=<secret>
AZURE_SUBSCRIPTION_ID=1ce493df-75e7-4c14-a20e-33af8d5bc18b
SENTINEL_RESOURCE_GROUP=darkpriorlabs
SENTINEL_WORKSPACE_NAME=dp-labs-dev
```

The last three lines bind the Sentinel workspace; they map to the
`--subscription-id`, `--resource-group`, and `--workspace-name` flags. They are
not in `.env.example`, so append them.

**Secrets go only in `.env`.** That file is gitignored. Never paste the real
client secret into chat, a ticket, a commit, or this guide. Use `<secret>` as a
placeholder everywhere except the actual `.env` file.

## Step 3. Seed the tenant

Seed these **intentionally weak** settings so the live checks exercise real
customer-facing findings. Prefer under-fire to over-fire on EXPOSED.

### Identity (default pack)

- [ ] **PIM unused / standing admin** — at least one Global Admin or Privileged Role Admin with permanent (not eligible) assignment
- [ ] **Identity Protection off** — no risk-based CA requiring MFA / password change on medium+ user/sign-in risk
- [ ] **CA gaps** — privileged roles without MFA grant; or MFA policy that excludes break-glass only (document the exclusion group)
- [ ] **Legacy auth open** — CA does not block legacy authentication for all users (or only a pilot) → EXPOSED class
- [ ] **MFA-less GA path** — a tier-0 / GA principal that can sign in without MFA (not the named break-glass exclusion) → EXPOSED class
- [ ] **Dormant privileged** — one privileged account with no successful sign-in in 90+ days

### Endpoint (default pack)

- [ ] **MDE onboard gap** — licensed MDE P2 seats >> onboarded machines (leave a visible gap)

### Email (off default packs)

- [ ] **Weak MDO** — preset Standard/Strict off or pilot-only; Safe Links/Attachments not org-wide
  (Not verified by Graph; portal/PowerShell only. The default dry-run does not depend on this firing.)

### Starter packs (optional contrast)

- [ ] Thin Sentinel rules / UEBA off (if workspace present)
- [ ] Purview DLP missing or simulation-only
- [ ] MDI sensors missing (if on-prem AD)

### Clean controls (false-positive pass)

- [ ] Named break-glass accounts excluded from MFA-less EXPOSED
- [ ] One healthy CA policy that correctly protects admins with MFA (so not everything is red)
- [ ] Friend-tenant pass: no EXPOSED on a cleanly configured control tenant

### Product validation

- [ ] `licenselens demo` → identity + endpoint moves, no email top-card move
- [ ] `licenselens quickstart` device-code path works end-to-end
- [ ] HTML report remains readable at desktop and mobile widths; finding filters update visible counts

## Step 4. Verify

Run the doctor preflight against the live tenant:

```bash
uv run licenselens doctor --live --auth client_secret --profile full
```

`--profile full` probes Graph, the Defender for Endpoint API, and the Sentinel
workspace. Expected: token ok, organization ok, subscribed SKUs present, and no
permission errors. If Graph returns 403, re-check admin consent and re-run.

Then a live scan:

```bash
uv run licenselens scan --live --auth client_secret -o reports-live
```

**Live reports contain tenant data.** Always write them under `reports-live/`,
not the demo `reports/` folder, and do not commit them. Treat every live report
as sensitive until you have scrubbed it.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings) |
| 1 | Completed with gap or partial findings |
| 2 | Auth / configuration / API error |

A seeded tenant should produce exit 1 (gap findings) for the scan. Exit 2 means
something is wrong with auth, consent, or the `.env` binding. Fix that before
continuing.

# App registration (live scans)

Security License Lens is **read-only**. Create a dedicated Entra ID app registration for assessments.

## 1. Register the application

1. Entra admin center → **App registrations** → **New registration**
2. Name: `Security License Lens` (or your firm’s name)
3. Supported account types: single tenant (typical)
4. No redirect URI required for client-credentials; for device code, add a public client if you use your own app

## 2. Choose an auth mode

| Mode | CLI | When to use |
|------|-----|-------------|
| Device code | `--live --auth device --tenant-id <tid> --client-id <cid>` | Interactive consultant laptop |
| Client secret | `--live --auth client_secret` + env vars | Automation, MSP runbooks, CI |
| Azure CLI | `--live --auth azure_cli` | You already ran `az login` |

Environment variables (standard Azure names):

```bash
export AZURE_TENANT_ID="<tenant-guid>"
export AZURE_CLIENT_ID="<app-id>"
export AZURE_CLIENT_SECRET="<secret>"   # client_secret mode only
```

## 3. API permissions (application, admin consent)

Minimum for **Session A** (SKU + organization):

| Permission | Type | Purpose |
|------------|------|---------|
| `Organization.Read.All` | Application | Tenant display name |
| `Organization.Read.All` covers org; SKUs use | | |
| `Directory.Read.All` **or** license-related read | Application | `subscribedSkus` |

Practical starter set used by this project (identity-first roadmap):

See [permissions.md](permissions.md). Grant **application** permissions and click **Grant admin consent**.

> `subscribedSkus` is available to apps with appropriate directory/organization directory reads. If Graph returns 403, add `Organization.Read.All` and `Directory.Read.All`, consent again, and re-run `licenselens doctor --live`.

## 4. Client secret (app-only)

Certificates are preferred long-term; client secret is fine for early pilots:

1. App → **Certificates & secrets** → **New client secret**
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
```

Expected: token ok, organization ok, subscribedSkus count &gt; 0.

## 6. Scan

```bash
licenselens scan --live --auth client_secret -o reports
open reports/security-license-lens-report.html
```

Configuration checks beyond entitlement mapping are still rolling out; the live report will note that clearly.

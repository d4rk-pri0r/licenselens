# MSP Friday ritual

Vendor-neutral multi-tenant workflow. No product branding in reports.

## Command

```bash
licenselens batch tenants.yaml -o reports
```

With live credentials (default live auth mode is **`client_secret`** when
`--live` is set):

```bash
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...

licenselens batch tenants.yaml -o reports --live
```

Full CLI flags: [CLI reference](cli.md). Fixture and comments:
[examples/tenants.yaml](https://github.com/d4rk-pri0r/licenselens/blob/main/examples/tenants.yaml).

## App-only auth (once per customer)

1. Entra ID → App registrations → New registration (single tenant or multi).
2. Certificates & secrets → client secret (certificate credentials are **not**
   implemented by LicenseLens).
3. API permissions (application) + **admin consent** — see
   [app-registration.md](app-registration.md) and [permissions.md](permissions.md).
4. Store `tenant_id`, `client_id`, and secret in a secrets manager — not in git.

Prefer `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` (and per-tenant `AZURE_TENANT_ID`
or YAML `tenant_id`) over embedding secrets in YAML.

## `defaults` + per-tenant merge

Top-level `defaults` is a map applied to every tenant. Each tenant entry is
merged on top: non-`null` per-tenant keys win.

```yaml
defaults:
  auth: client_secret
  # packs default to identity + endpoint when omitted

tenants:
  - slug: contoso
    tenant_id: "11111111-2222-3333-4444-555555555555"
  - slug: fabrikam
    tenant_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    workspace_resource_id: "/subscriptions/.../workspaces/..."
```

## Tenant keys

Every key `run_batch` reads:

| Key | Notes |
|-----|--------|
| `slug` | Report directory name (falls back to `tenant_id`) |
| `tenant_id` | Entra tenant GUID |
| `azure_tenant_id` | Alias for `tenant_id` |
| `auth` / `auth_mode` | Values: `dry-run`, `device`, `client-secret`, `azure-cli` (underscore variants of these values are also accepted) |
| `client_id` | App registration id (else `AZURE_CLIENT_ID`) |
| `client_secret` | Accepted in YAML but **must not be committed**; prefer `AZURE_CLIENT_SECRET` |
| `packs` | List or comma-separated pack ids. Default packs are **identity + endpoint** (not `starter`) |
| `allow_email_proxy` | Opt into labeled Secure Score email path (email pack off by default) |
| `profile` | Profile id |
| `config` | Path to a custom profile/config YAML |
| `rules` | Path to extra rules YAML |
| `backend` / `backends` | Collector backends (string or list) |
| `report_archive` | Write `security-license-lens-report.zip` for that tenant |
| `workspace_resource_id` | Sentinel workspace ARM id |
| `discover_workspaces` | Auto-select only when **exactly one** Sentinel workspace exists |

Email is **off by default** (no Graph API for MDO policy config). Only set
`allow_email_proxy: true` when the customer accepts a labeled Secure Score
degraded path.

### Secrets warning

`client_secret` in YAML is accepted by the code path, but real values must never
be committed. Prefer environment variables and a secrets manager.

## Output layout

Batch is the only command that nests reports:

```text
reports/<slug>/<timestamp>/security-license-lens-report.{html,json,md}
reports/index.md
```

Single-tenant `scan` / `demo` / `quickstart` write **flat** into `-o` — see
[Report and export](report.md).

## Failure behavior

One failing tenant is **recorded** in the summary rows and `index.md`; the batch
**continues** with the remaining tenants. A single failure does not abort the
batch.

## Index sort

`index.md` lists tenants with **exposed** findings first (then by exposure count
and realized %), so the Friday triage order is fix-exposed-first. Open each
tenant HTML for the same top-card contract as a single scan.

## Friday batch

```bash
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...

licenselens batch tenants.yaml -o reports/$(date +%Y-%m-%d) --live
open reports/$(date +%Y-%m-%d)/index.md
```

## Monthly diff

Point `diff` at two per-tenant JSON paths (note the slug/timestamp layout):

```bash
licenselens diff \
  reports/2026-07-01/contoso/<timestamp>/security-license-lens-report.json \
  reports/2026-08-01/contoso/<timestamp>/security-license-lens-report.json \
  -o reports/contoso-diff.md
```

## Notes

- Read-only. Advisory only. Confirm in the portal before change tickets.
- Default packs for the top-card rollup are **identity + endpoint**. The
  `starter` pack exists but is not the batch default; pass it explicitly via
  `packs` or CLI `--pack` only when you want it.
- JSON/ZIP reports contain `tenant_id` and evidence — treat as sensitive
  ([report.md](report.md)).

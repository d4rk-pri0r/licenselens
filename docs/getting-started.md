# Getting started

## Install (dev)

```bash
git clone https://github.com/d4rk-pri0r/licenselens.git
cd licenselens
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Dry-run scan

```bash
licenselens version
licenselens checks
licenselens scan -o reports
```

Open `reports/security-license-lens-report.html` in a browser.

## Quick demo

```bash
licenselens demo -o reports --open
```

Runs the offline demo tenant, prints the executive summary to the terminal,
writes the HTML report, and optionally opens it in your browser. The report is
from curated demo data — not a real tenant.

## Docker

Run the offline demo in a container and collect reports via a mounted volume:

```bash
docker build -t licenselens .
mkdir -p reports
docker run --rm -v "$PWD/reports:/reports" licenselens
# or explicitly:
docker run --rm -v "$PWD/reports:/reports" licenselens demo -o /reports
```

`licenselens` is the image entrypoint, so any command works:

```bash
docker run --rm -v "$PWD/reports:/reports" licenselens scan --live --auth device -o /reports
docker run --rm licenselens version
docker run --rm licenselens checks
```

> Note: `--auth device` needs an interactive terminal; add `-it`:
> `docker run --rm -it -v "$PWD/reports:/reports" licenselens scan --live --auth device -o /reports`

## Sample report

A scrubbed dry-run report is committed at `examples/sample-report/` so you can
preview HTML output without a tenant.

## Compare two scans (diff)

Run a scan, apply a fix, re-run, then diff the two JSON artifacts:

```bash
licenselens scan -o reports  # baseline
licenselens scan -o reports  # after changes (new timestamped report)
licenselens diff reports/old.json reports/new.json -o reports/diff.md
```

The diff groups checks into **new gaps**, **resolved**, **improved**, **worsened**
and unchanged, and lists confidence changes. Use `-o diff.json` for a machine-readable
version.

## Discover a Sentinel workspace

Instead of pasting an ARM resource ID, let the tool find Sentinel-capable workspaces:

```bash
licenselens discover-workspace --auth client_secret
```

Pass `--subscription-id` to limit the search or `--max-subscriptions` to cap it.
The command prints one workspace ARM resource ID per line; use one with
`scan --workspace-resource-id` or with the `discover_workspaces: true` batch option.

## Batch multi-tenant scans (MSPs)

Create a `tenants.yaml` listing each tenant, then run one batch:

```yaml
tenants:
  - slug: contoso
    tenant_id: 11111111-1111-1111-1111-111111111111
    auth_mode: client_secret            # optional per tenant
    workspace_resource_id: ""           # optional
    discover_workspaces: true           # auto-find a single Sentinel workspace
  - slug: fabrikam
    tenant_id: 22222222-2222-2222-2222-222222222222
```

```bash
licenselens batch tenants.yaml -o reports
```

Per-tenant reports land under `reports/<slug>/<timestamp>/` and a summary
`index.md` is written next to them. A failing tenant is recorded in the index
and the batch continues.

## Live scan (identity pack)

1. Register an app and grant admin consent — [app-registration.md](app-registration.md)
2. Preflight:

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
licenselens doctor --live --auth client_secret
```

`--profile full` also probes the Defender for Endpoint API and, when you pass
`--workspace-resource-id`, the Sentinel workspace:

```bash
licenselens doctor --live --auth client_secret --profile full \
  --workspace-resource-id "/subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/..."
```

3. Scan:

```bash
licenselens scan --live --auth client_secret -o reports
```

Interactive alternative:

```bash
licenselens scan --live --auth device \
  --tenant-id "$AZURE_TENANT_ID" \
  --client-id "$AZURE_CLIENT_ID" \
  -o reports
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings) |
| 1 | Completed with gap or partial findings |
| 2 | Auth/config/Graph error |

# CLI reference

Command-line surface for `licenselens` as implemented in the package. Flags and
environment variables always override interactive prompts.

## Commands

### `version`

Print the product and package version.

```bash
licenselens version
```

No options.

### `setup`

Print the Entra app-registration scaffold: where to find the tenant ID, the
app-registration steps (device-code public client or app-only client secret),
the 15 read-only Graph permissions with a one-line purpose each, the
admin-consent URL, and the `--tenant-id` / `--client-id` / `--client-secret`
flags and env vars for the next step. The permission list is printed from the
same constant the auth layer enforces (`REQUIRED_GRAPH_APP_PERMISSIONS`).

Offline only — no network calls, no prompts, safe for non-TTY use and
idempotent. `init` is an alias.

```bash
licenselens setup
```

No options. Exit `0`. See [App registration](app-registration.md) for the full
walkthrough.

### `checks`

List every registered check with ID, workload, severity, profiles, backend,
evaluation mode, and support state.

```bash
licenselens checks
```

No options. Exit `0` even when the catalog is empty.

### `doctor`

Preflight credentials and core Graph permissions. Optionally probe MDE and
Sentinel, and print assessment-profile requirements before any token request.
With `--profile full` and a workspace or subscription scope supplied, doctor
also probes the Sentinel onboarding state and the Defender for Cloud pricings
(same ARM reads the scan uses); both rows are optional warnings on denial.

| Option | Default | Description |
|--------|---------|-------------|
| `--live` / `--dry-run` | dry-run | Probe a real tenant (`--live`) or print dry-run messaging only |
| `--auth` | (live default: device) | `device` \| `client_secret` \| `azure_cli` |
| `--profile` | `basic` | **Probe depth**, not an assessment id: `basic` (core Graph) or `full` (also MDE API, Sentinel onboarding, and Defender for Cloud pricings) |
| `--assessment-profile` | — | Profile id (e.g. `identity`, `full`). Repeatable. Validated before auth |
| `--tenant-id` | env `AZURE_TENANT_ID` | Directory (tenant) ID |
| `--client-id` | env `AZURE_CLIENT_ID` | App registration client ID |
| `--client-secret` | env `AZURE_CLIENT_SECRET` | Client secret (prefer the env var) |
| `--workspace-resource-id` | env `SENTINEL_WORKSPACE_RESOURCE_ID` | Sentinel / Log Analytics workspace ARM resource ID |
| `--subscription-id` | env `AZURE_SUBSCRIPTION_ID` | Used with resource group + workspace name to synthesize an ARM id |
| `--resource-group` | env `SENTINEL_RESOURCE_GROUP` | Sentinel resource group |
| `--workspace-name` | env `SENTINEL_WORKSPACE_NAME` | Sentinel workspace name |

Exit `0` when ready (optional probes may still warn). Exit `2` when not ready or
on auth/config failure.

```bash
licenselens doctor --live --auth client_secret --profile full
licenselens doctor --assessment-profile identity --assessment-profile full
```

### `scan`

Run entitlement-aware checks and write HTML, JSON, and Markdown reports.

In an interactive TTY, missing options are prompted. Without a TTY, the default
is dry-run; `--live` without credentials exits with a clear error.

| Option | Default | Description |
|--------|---------|-------------|
| `-o` / `--output-dir` | `reports` | Directory for report files |
| `-w` / `--workload` | — | Limit to one or more workloads (repeatable). See [Workloads vs packs](#workloads-vs-packs) |
| `--live` / `--dry-run` | (TTY: prompt; no TTY: dry-run) | Query a real tenant vs curated demo data |
| `--auth` | (live default: device) | `device` \| `client_secret` \| `azure_cli` \| `oidc` |
| `--tenant-id` | env `AZURE_TENANT_ID` | Directory (tenant) ID |
| `--client-id` | env `AZURE_CLIENT_ID` | App registration client ID |
| `--client-secret` | env `AZURE_CLIENT_SECRET` | Client secret (prefer the env var) |
| `--workspace-resource-id` | env `SENTINEL_WORKSPACE_RESOURCE_ID` | Sentinel workspace ARM id (required for live Sentinel checks) |
| `--subscription-id` | env `AZURE_SUBSCRIPTION_ID` | With resource group + workspace name, synthesizes an ARM id |
| `--resource-group` | env `SENTINEL_RESOURCE_GROUP` | Sentinel resource group |
| `--workspace-name` | env `SENTINEL_WORKSPACE_NAME` | Sentinel workspace name |
| `--pack` | identity + endpoint | Packs for the top-card rollup (repeatable). Email is off by default |
| `--allow-email-proxy` / `--no-email-proxy` | off | Opt into a labeled Secure Score proxy for the email pack |
| `--open` / `--no-open` | off | Open the HTML report in a browser |
| `--profile` | — | **Profile id** (`core`, `identity`, `full`, …). Omit for legacy full scope |
| `--config` | — | Organization profile YAML overlay (validated before auth) |
| `--rules` | — | Custom rules YAML (list or `{custom_rules: [...]}`); validated before auth |
| `--backend` | — | Preferred collection backend(s): `graph`, `arm`, `exchange_online`, `defender`, `secure_score`, `manual` (repeatable) |
| `--report-archive` / `--no-report-archive` | off | Also write `security-license-lens-report.zip` |

```bash
licenselens scan --live --auth client_secret --profile identity -o reports
licenselens scan --dry-run -o reports
```

Exit `0` when the scan finishes with no gap/partial findings; `1` when it
completes with gap or partial findings; `2` on auth, configuration, or API
errors.

### `demo`

Offline demo scan against curated sample data (not a real tenant). Always exits
`0` on success.

| Option | Default | Description |
|--------|---------|-------------|
| `-o` / `--output-dir` | `reports` | Directory for the demo report |
| `--open` / `--no-open` | off | Open the HTML report in a browser |
| `--profile` | — | Profile id |
| `--config` | — | Organization profile YAML overlay |
| `--rules` | — | Custom rules YAML |
| `--backend` | — | Preferred collection backend(s) (repeatable) |
| `--report-archive` / `--no-report-archive` | off | Also write a deterministic offline report ZIP |
| `--after` / `--before` | before | Run the after-remediation demo scenario (applies a deterministic overlay to the evidence so a `diff` against the baseline shows closed gaps) |

```bash
licenselens demo -o reports --open
licenselens demo -o before --export json
licenselens demo -o after --after --export json
licenselens diff before/security-license-lens-report.json after/security-license-lens-report.json
```

### `ui`

Local loopback wizard (127.0.0.1 only). No telemetry. Does not bind other
interfaces. Browser opening is opt-in.

| Option | Default | Description |
|--------|---------|-------------|
| `--demo` | off | Run the offline demo path |
| `--open` / `--no-open` | off | Open the wizard in a browser |
| `--host` | `127.0.0.1` | Bind address; non-loopback exits `2` |
| `--port` | `8765` | Port; `0` picks an ephemeral port |
| `-o` / `--output-dir` | `reports` | Directory for reports |
| `--profile` | `core` | Scan profile id |

Non-interactive terminals: `ui` without `--demo` exits `2` and does not hang.
`ui --demo` in a non-interactive terminal runs the offline scan and prints the
report path without serving.

```bash
licenselens ui --demo --open
```

### `quickstart`

Guided read-only live scan against your own tenant. Uses device code unless
`--client-secret` (or `AZURE_CLIENT_SECRET`) is set, then client-secret auth.
Runs doctor preflight and confirms before scanning.

| Option | Default | Description |
|--------|---------|-------------|
| `-o` / `--output-dir` | `reports` | Directory for scan reports |
| `--tenant-id` | env `AZURE_TENANT_ID` | Directory (tenant) ID |
| `--client-id` | env `AZURE_CLIENT_ID` | App registration client ID |
| `--client-secret` | env `AZURE_CLIENT_SECRET` | Optional app-only secret |
| `--profile` | — | Profile id |
| `--config` | — | Organization profile YAML overlay |
| `--rules` | — | Custom rules YAML |
| `--backend` | — | Preferred collection backend(s) (repeatable) |
| `--report-archive` / `--no-report-archive` | off | Also write a deterministic offline report ZIP |

```bash
licenselens quickstart -o reports
```

Exit codes match `scan` (`0` / `1` / `2`). Canceling the confirm prompt exits `0`
without writing a scan.

### `diff`

Compare two scan JSON artifacts by `check_id`.

| Argument / option | Default | Description |
|-------------------|---------|-------------|
| `OLD_JSON` | (required) | Baseline scan JSON report |
| `NEW_JSON` | (required) | Newer scan JSON report |
| `-o` / `--output` | `<new>-diff.md` | Output path (`.md` or `.json`) |

```bash
licenselens diff reports/before.json reports/after.json -o reports/diff.md
```

Exit `0` on success; `2` if a file is missing or the diff fails.

### `batch`

Run scans for every tenant listed in a `tenants.yaml` config. One failing tenant
is recorded and the batch continues; the process exit code is `2` if any tenant
errored, otherwise `0`.

| Argument / option | Default | Description |
|-------------------|---------|-------------|
| `CONFIG` | (required) | Path to `tenants.yaml` |
| `-o` / `--output-dir` | `reports` | Root directory for per-tenant reports and `index.md` |
| `--live` / `--dry-run` | dry-run | Live scans vs demo data per tenant |
| `--profile` | — | Default profile for tenants that omit `profile` |
| `--rules` | — | Default custom rules YAML for the batch |
| `--backend` | — | Default preferred backend(s) (repeatable) |
| `--report-archive` / `--no-report-archive` | off | Write a deterministic offline report ZIP per tenant |

```bash
licenselens batch tenants.yaml -o reports
```

Per-tenant keys and defaults are documented in [MSP batch auth](msp-batch.md) and
`examples/tenants.yaml`.

### `discover-workspace`

Discover Sentinel-capable Log Analytics workspaces and print their ARM resource
IDs (one per line). Always runs live auth.

| Option | Default | Description |
|--------|---------|-------------|
| `--auth` | device | `device` \| `client_secret` \| `azure_cli` |
| `--tenant-id` | env `AZURE_TENANT_ID` | Directory (tenant) ID |
| `--client-id` | env `AZURE_CLIENT_ID` | App registration client ID |
| `--client-secret` | env `AZURE_CLIENT_SECRET` | Client secret (prefer the env var) |
| `--subscription-id` | env `AZURE_SUBSCRIPTION_ID` | Restrict discovery to one subscription |
| `--max-subscriptions` | `10` | Cap on subscriptions scanned during discovery |

```bash
licenselens discover-workspace --auth client_secret
```

Exit `0` when at least one workspace is found; `1` when none are discovered;
`2` on auth or API failure.

### `mcp`

Start the LicenseLens MCP (Model Context Protocol) server over stdio so AI
assistants such as Claude Code or Cursor can run a security posture assessment
as a tool call. The server exposes a single read-only tool, `posture.assess`,
which defaults to the offline demo (curated sample data, no tenant contact);
a live assessment is opt-in and uses read-only, environment-based credentials.
It never mutates tenant configuration, and interactive device sign-in is not
available over MCP — use `licenselens scan --live` in a terminal instead.

This command requires the optional `mcp` extra:

```bash
pipx install 'licenselens[mcp]'
# or
uv pip install '.[mcp]'
```

| Option | Default | Description |
|--------|---------|-------------|
| (none) | — | The server has no options; configuration comes from the tool call arguments and standard `AZURE_*` environment variables |

```bash
# Start the MCP server (blocks; stdio is the wire)
licenselens mcp
```

Exit blocks serving tool calls over stdio until the client disconnects; `2`
when the `mcp` extra is not installed.

### `merge-reports`

Merge sibling tenant report JSONs into one single-file HTML dashboard with a
client-side tenant switcher. Reads each tenant's
`security-license-lens-report.json` (from a directory scan or an explicit list),
inlines every payload into a single offline HTML document, and applies the
**union** of every tenant's redaction targets so a cross-tenant identifier is
scrubbed from every region. No network requests at view time.

| Argument / option | Default | Description |
|-------------------|---------|-------------|
| `DIR` | (optional) | Directory to scan recursively for `security-license-lens-report.json` files |
| `--reports` | — | Explicit report JSON file paths (repeatable). Overrides `DIR` |
| `-o` / `--output` | (required) | Output path for the merged single-file HTML report |

```bash
# Merge every tenant report under a batch output root
licenselens merge-reports reports -o reports/merged.html

# Merge an explicit list of report JSONs
licenselens merge-reports \
  --reports reports/contoso/security-license-lens-report.json \
  --reports reports/fabrikam/security-license-lens-report.json \
  -o reports/merged.html
```

Exit `0` on success; `2` when the directory is missing, no report JSON files are
found, or the merge fails.

## Auth modes

CLI `--auth` values:

| CLI value | Typical use |
|-----------|-------------|
| `device` | Interactive device-code sign-in (live default when `--auth` is omitted) |
| `client_secret` | App-only client credentials (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`) |
| `azure_cli` | Reuse an existing `az login` session |
| `oidc` | GitHub Actions OIDC workload-identity federation (no stored client secret) |

`oidc` mints an Azure `ClientAssertionCredential` from a GitHub Actions OIDC
token (fetched from the `ACTIONS_ID_TOKEN_REQUEST_URL` /
`ACTIONS_ID_TOKEN_REQUEST_TOKEN` runtime env, or passed explicitly). It requires
`AZURE_TENANT_ID` + `AZURE_CLIENT_ID` and is the auth mode used by the scheduled
[continuous-assessment](msp-batch.md) workflow. See [MSP batch auth](msp-batch.md).

Dry-run / demo paths never call Microsoft APIs.
See [App registration](app-registration.md) for permission setup.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings), or a non-scan command completed cleanly |
| 1 | Scan completed with gap or partial findings; or `discover-workspace` found nothing |
| 2 | Auth, configuration, or API error |

`scan` and `quickstart` use `0` / `1` based on actionable gaps. `batch` exits `2`
if any tenant row has status `error`, otherwise `0`. `doctor` exits `2` when the
tenant is not ready for identity scanning.

## Environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `AZURE_TENANT_ID` | doctor, scan, quickstart, discover-workspace | Directory (tenant) ID |
| `AZURE_CLIENT_ID` | doctor, scan, quickstart, discover-workspace | App registration client ID |
| `AZURE_CLIENT_SECRET` | doctor, scan, quickstart, discover-workspace | Client secret (prefer over `--client-secret`) |
| `AZURE_SUBSCRIPTION_ID` | doctor, scan, discover-workspace | Azure subscription; with resource group + workspace name synthesizes a Sentinel ARM id; also scopes workspace discovery |
| `SENTINEL_WORKSPACE_RESOURCE_ID` | doctor, scan | Full workspace ARM resource ID (wins over the three-part synthesis) |
| `SENTINEL_RESOURCE_GROUP` | doctor, scan | Resource group for ARM id synthesis |
| `SENTINEL_WORKSPACE_NAME` | doctor, scan | Workspace name for ARM id synthesis |

If `SENTINEL_WORKSPACE_RESOURCE_ID` is set, it is used as-is. Otherwise
`AZURE_SUBSCRIPTION_ID` + `SENTINEL_RESOURCE_GROUP` + `SENTINEL_WORKSPACE_NAME`
must all be present to build the ARM id.

## The `--profile` collision

`--profile` means different things on different commands:

| Command | `--profile` means | Profiles use |
|---------|-------------------|-------------------------|
| `doctor` | Probe depth: `basic` (default) or `full` | `--assessment-profile` (repeatable) |
| `scan`, `demo`, `quickstart`, `batch` | Profile id (`core`, `identity`, `full`, …) | `--profile` |

Examples:

```bash
# doctor: probe depth
licenselens doctor --live --profile full

# doctor: list requirements for profiles (no token until after validation)
licenselens doctor --assessment-profile identity

# scan: profile id
licenselens scan --live --auth client_secret --profile identity -o reports
```

Profile selection on scan uses `--profile` only (the doctor-only
`--assessment-profile` flag does not exist on scan).

## Workloads vs packs

Two separate enums:

**Workloads** (`--workload` / `-w` on `scan`) filter which check YAML trees run.
Valid values:

`identity`, `defender`, `sentinel`, `purview`, `endpoint`, `exchange`,
`collaboration`, `teams`, `power_platform`, `power_bi`, `intune`, `azure`,
`general`

**Packs** (`--pack` on `scan`, and per-tenant `packs` in batch) control top-card
ranking and rollup, not which checks are enabled. Valid values:

`identity`, `email`, `endpoint`, `collaboration`, `power-platform`, `power-bi`,
`starter`

Default packs are **`identity` + `endpoint`**. Email is a **pack**, not a
workload (do not pass `email` to `--workload`). The email pack is off by default
because MDO policy config has no Graph read API (PowerShell-only); use
`--allow-email-proxy` only if you explicitly want a labeled Secure Score path.

## Profiles / `--config` / `--rules` / `--backend`

On `scan`, `demo`, `quickstart`, and `batch`:

| Flag | Role |
|------|------|
| `--profile` | Built-in profile id (`core`, `identity`, `full`, `email`, `collaboration`, `endpoint`, `data-protection`, `secops`, `power-platform`, `power-bi`, `scuba`, …). Omit for legacy full scope |
| `--config` | Organization YAML overlay merged onto the selected profile (validated before auth) |
| `--rules` | Custom rules YAML — a list, or `{custom_rules: [...]}` (validated before auth) |
| `--backend` | Preferred collection backend(s), repeatable: `graph`, `arm`, `exchange_online`, `defender`, `secure_score`, `manual` |

Invalid profile/config/rules fail with exit `2` before any token request.
Built-in profile tables live in the [generated profiles reference](reference/profiles.md).
Operator guidance: [Profiles & custom rules](profiles.md).

## Output files

### `scan` / `demo` / `quickstart`

Write **flat** into `-o` / `--output-dir` (default `reports`):

| File | Contents |
|------|----------|
| `security-license-lens-report.html` | Offline HTML dashboard |
| `security-license-lens-report.json` | Machine-readable findings (includes `tenant_id` and evidence — treat as sensitive) |
| `security-license-lens-report.md` | Markdown summary |
| `security-license-lens-report.zip` | Only with `--report-archive` |

There is no per-tenant slug or timestamp subdirectory for single-tenant commands.

### `batch`

Under `-o` (default `reports`):

- `reports/<slug>/<timestamp>/security-license-lens-report.{html,json,md}`
- optional ZIP in the same tenant directory when `--report-archive` is set
- `reports/index.md` — batch index (exposed tenants sorted first)

### `diff`

Writes a single file at `-o` / `--output`, or defaults to
`<new-json-stem>-diff.md` beside the newer JSON artifact.

## Copy-paste examples

```bash
licenselens demo -o reports --open
licenselens scan --live --auth client_secret --profile identity -o reports
licenselens batch tenants.yaml -o reports
```

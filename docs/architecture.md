# Architecture

## Pipeline

```
Auth → collect_scan_state → evaluate licensed checks
     → profile / custom rules → rank / rollup → HTML / JSON / MD (+ optional ZIP)
```

1. **Auth** — implemented modes: device code (`device`), client
   secret (`client_secret`), and Azure CLI (`azure_cli`). Dry-run uses curated
   sample data without a live credential. See [CLI reference](cli.md) for flags
   and env vars.
2. **`collect_scan_state`** — resolves owned SKUs / service plans, then runs the
   collectors selected for the scan (workload filters, profile backend
   preferences, and optional `--backend` order). Evidence is keyed for
   evaluators; collection summaries record what succeeded or was skipped.
3. **Evaluate licensed checks** — YAML checks under `checks/<workload>/` run only
   when required capabilities are owned. Missing entitlements yield
   `not_licensed` instead of a false gap.
4. **Profile / custom rules** — optional profile overlays and custom
   rules adjust findings after the base evaluation (accepted risk, pack scope,
   backend preferences). Profile `RedactionSettings` are accepted on the schema
   and merged into the resolved profile, but are **not** applied to HTML/JSON/MD
   report bodies today.
5. **Rank / rollup** — priority packs (default identity + endpoint) shape the
   top-card moves and capability rollup; findings stay ranked by status and
   severity.
6. **Reports** — static HTML dashboard, portable JSON, and Markdown. Optional
   `--report-archive` adds a ZIP beside those files.

There is no hosted SaaS control plane: the CLI runs locally (or in your CI),
talks to Microsoft APIs with your credentials, and writes artifacts to disk.

## Output layout

**`scan` / `demo` / `quickstart`** write report files **flat** into `-o` /
`--output-dir` (default `reports`):

```
reports/
  security-license-lens-report.html
  security-license-lens-report.json
  security-license-lens-report.md
  security-license-lens-report.zip   # only with --report-archive
```

**Only `batch`** nests per tenant under slug and UTC timestamp, plus a batch
index:

```
reports/
  <tenant-slug>/<timestamp UTC>/
    security-license-lens-report.{html,json,md}
  index.md
```

`diff` compares two `*.json` artifacts by `check_id` and emits Markdown or JSON.

## Collector families

Collectors are read-only. Families include:

| Family | Role |
|--------|------|
| Microsoft Graph | SKUs, Conditional Access, roles/PIM, sign-ins, guests, apps, Intune, Secure Score, and related directory/security reads |
| Defender for Endpoint (MDE) | Machine inventory / onboard signals |
| Azure Resource Manager (ARM) | Sentinel alert rules, settings, workspace discovery |
| Public DNS | SPF / DKIM / DMARC and related mail-auth records |
| PowerShell bridge | Allowlisted read-only adapters (`powershell/LicenseLens.Collectors`) for surfaces without a Graph read API |

Operator-facing backend tokens and the bridge contract are documented in
[Collectors](collectors.md). Full command and flag surface: [CLI reference](cli.md).
Contributor registry metadata lives in
`src/licenselens/engine/_registry_source_meta.py`.

## Workspace discovery

- `collectors/workspace_discover.py` enumerates subscriptions (ARM), lists
  Log Analytics workspaces, and probes each for a
  `Microsoft.SecurityInsights/alertRules` response to decide whether it hosts
  Sentinel.
- `run_scan(..., discover_workspaces=True)` auto-selects a workspace only when
  exactly one Sentinel-capable workspace is found; otherwise it warns and
  refuses to guess.

## Key types

- `SubscribedSku` / `ServicePlan` — tenant entitlements
- `Capability` — product feature unlocked by entitlements, plus plain-language
  `plain_name`, `outcome`, `why_it_matters`, `if_unused` for customer reports
- `CheckDefinition` — declarative check metadata, including `customer_title`,
  `customer_summary`, `customer_next_step`
- `Finding` — result with status `gap | partial | ok | not_licensed | error | skipped`
  and mirrored customer-facing fields
- `CapabilitySummary` — owned capabilities ready for the “What you already pay for” section
- `ScanResult` — full portable scan artifact, including `recommended_next_steps`

## Extensibility

- Add capabilities in `catalog/capabilities.yaml`
- Add checks as YAML under `checks/<workload>/`
- Implement collectors named in check `collector` fields
- Register pure evaluators in `engine/evaluate.py` (`EVALUATORS`)
- Keep reporting format stable so MSPs can archive JSON over time

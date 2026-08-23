# MSP Product-Fit Audit — §15 of the product-maturity goal

**Scope.** This document reviews the current multi-tenant implementation of
Security License Lens against the target MSP workflow:

> PORTFOLIO OF CUSTOMER TENANTS → ASSESS ENTITLEMENTS → IDENTIFY SECURITY
> ACTIVATION GAPS → PRIORITIZE BY RISK/VALUE/CUSTOMER → CREATE IMPLEMENTATION
> BACKLOG → DELIVER PROJECT/MANAGED SERVICE WORK → REASSESS → SHOW IMPROVEMENT
> DURING QBR.

Every claim is grounded in the actual code and docs. Where a capability is
absent, that is stated plainly as a gap with a pointer to where it lives. This
is an analysis document only — no code, YAML, or docs were modified.

---

## 1. Current state summary

The product already delivers a credible **single-run, per-tenant assessment**
with a multi-tenant batch wrapper:

- `licenselens batch tenants.yaml -o reports` runs one scan per tenant and
  writes `reports/<slug>/<timestamp>/security-license-lens-report.{html,json,md}`
  plus a summary `index.md` (`src/licenselens/batch.py:71-204`,
  `docs/msp-batch.md:126-133`).
- The batch is **read-only** against tenants (`docs/permissions.md:3`,
  `SECURITY.md:27`), ships **no telemetry** (`SECURITY.md:28`), and reports are
  **redacted by default** (`docs/limitations.md:43`, `docs/profiles.md:151-181`).
- The entitlement→capability→gap model is the product's core differentiator
  (`docs/methodology/assessment-model.md:7-28`).
- A `merge-reports` command produces a single-file cross-tenant dashboard
  (`src/licenselens/cli.py:1258-1310`, `docs/report.md:90-107`).
- A `diff` command compares two scan JSON artifacts by `check_id`
  (`src/licenselens/diff_report.py:14-79`, `docs/msp-batch.md:160-169`).

The honest gap is that the product is strong at **step 2 (assess)** and
**step 3 (identify gaps)** of the workflow, but the surrounding MSP lifecycle —
onboarding, isolation, prioritization across the portfolio, backlog generation,
repeated-assessment history, and QBR presentation — is largely **manual glue
around the CLI**, not product features.

---

## 2. Workflow-by-workflow assessment

### 2.1 Portfolio of customer tenants (onboarding)

**Current state.** Tenants are declared in a single `tenants.yaml` with a
top-level `defaults` map merged over per-tenant entries
(`src/licenselens/batch.py:36-50`, `docs/msp-batch.md:77-93`). Each tenant
carries `slug`, `tenant_id`, `auth`/`auth_mode`, `client_id`, `client_secret`,
`packs`, `profile`, `config`, `rules`, `backend`, `workspace_resource_id`, and
`discover_workspaces` (`docs/msp-batch.md:97-119`). Secrets are preferred via
env vars (`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`) over YAML
(`docs/msp-batch.md:33-34`, `docs/msp-batch.md:121-124`).

**Gaps.**
- **No tenant inventory/CRM.** The portfolio lives in a hand-maintained YAML
  file. There is no import from a PSA (ConnectWise, Autotask), no discovery of
  tenants under a partner/CSP agreement, and no per-customer metadata (owner,
  contract tier, SLA, risk appetite, service level). Pointer:
  `examples/tenants.yaml` and `docs/msp-batch.md:97-119`.
- **No onboarding checklist or state machine.** Nothing tracks whether a tenant
  has been onboarded (app registered, consent granted, secret stored) versus
  pending. `licenselens doctor --live` is the closest preflight
  (`src/licenselens/doctor.py:95-107`), but it is a per-run probe, not a
  persistent onboarding record.
- **No per-tenant credential store.** The batch reads one `client_id` /
  `client_secret` per tenant from YAML or env. There is no integration with a
  secrets manager, no per-tenant secret rotation, and no way to reference a
  secret by name rather than by value. Pointer: `src/licenselens/batch.py:122-127`
  passes `entry.get("client_secret")` straight into `build_auth_context`.

### 2.2 Assess entitlements

**Current state.** This is the product's core strength. Each scan reads
`organization/subscribedSkus`, matches service-plan GUIDs to catalog
capabilities (`catalog/capabilities.yaml`), and evaluates only checks whose
required capability is owned (`docs/methodology/entitlement-model.md:10-34`,
`docs/methodology/assessment-model.md:95-107`). Unlicensed capabilities report
`not_licensed`, never a false gap. The default packs are **identity + endpoint**
(`docs/msp-batch.md:174-176`).

**Gaps.**
- **Email pack off by default.** MDO policy config has no Graph read API; it is
  PowerShell-only, so the email pack is off unless `allow_email_proxy: true` is
  set, and even then it is a labeled Secure Score proxy
  (`docs/msp-batch.md:117-119`, `docs/limitations.md:16-21`). For an MSP selling
  email security, this is a visible coverage hole.
- **PowerShell bridge is single-cloud.** The allowlisted bridge supports the
  **public** cloud only (`docs/limitations.md:48-50`). GCC/GCC High/DoD tenants
  cannot be fully assessed for email/collaboration surfaces.
- **National-cloud selection is not user-selectable.** Graph/ARM/MDE base URLs
  are modeled in `src/licenselens/cloud_endpoints.py` but there is no CLI cloud
  flag (`docs/permissions.md:35-38`). An MSP serving government tenants cannot
  point the tool at a sovereign cloud.

### 2.3 Identify security activation gaps

**Current state.** Findings are deterministic, evidence-backed, and expose
`you pay for X → expected Y → observed Z` (`README.md:5-6`,
`docs/methodology/assessment-model.md:7-28`). The report ranks gaps into
"top moves" with effort, timeline, and a deep link to the admin page
(`docs/report.md:144-151`). The batch `index.md` sorts **exposed** tenants first
(`src/licenselens/batch.py:192-200`, `docs/msp-batch.md:144-148`).

**Gaps.**
- **No cross-tenant gap aggregation.** The `index.md` is a flat table of
  per-tenant counts (gaps, exposed, realized %, worst move). There is no
  portfolio-level view of "which gaps recur across N tenants" or "which control
  is most commonly left at default across the book of business." Pointer:
  `src/licenselens/batch.py:85-93` (the index columns).
- **No risk/value scoring.** Findings carry severity and effort, but there is no
  portfolio-level risk × value × customer-priority ranking. The `merge-reports`
  dashboard is a client-side tenant switcher, not a prioritization engine
  (`docs/report.md:90-107`).

### 2.4 Prioritize by risk/value/customer

**Current state.** Per-tenant, the report ranks moves by severity/effort
(`docs/report.md:144-151`). Profiles support `severity_override` to reclassify a
check's severity per tenant or per organization (`docs/profiles.md:76-89`), and
`exclusions`/`annotations`/`omissions` record accepted-risk and ownership
decisions (`docs/profiles.md:91-116`).

**Gaps.**
- **No portfolio-level prioritization.** Prioritization is per-tenant only.
  There is no mechanism to rank tenants against each other by risk, contract
  value, or customer priority. The batch index sorts only by exposed-count then
  realized % (`src/licenselens/batch.py:169-174`).
- **No customer-priority field.** `tenants.yaml` has no `priority`/`tier`/`sla`
  key that feeds prioritization. The schema is fixed to the keys in
  `docs/msp-batch.md:97-119`.

### 2.5 Create implementation backlog

**Current state.** `scan`/`demo`/`quickstart` accept `--export action-plan|csv|json`
to write a deterministic remediation action plan CSV/JSON with `check_id`,
`title`, `severity`, `effort`, `timeline`, `reason`, `customer_next_step`, and
`deep_link` (`docs/report.md:55-75`). This is the closest thing to a backlog.

**Gaps.**
- **`--export` is not wired into `batch`.** The action-plan export is documented
  only for `scan`/`demo`/`quickstart` (`docs/report.md:56-58`). The `batch`
  command (`src/licenselens/cli.py:1314-1347`) has no `--export` option, so a
  multi-tenant run produces no per-tenant action-plan files. An MSP must run
  each tenant individually to get a backlog CSV.
- **No backlog aggregation or tracking.** There is no merged backlog across
  tenants, no status field (open/in-progress/done), no assignment, and no
  linkage from a finding to a work item. The action plan is a static export, not
  a living backlog.

### 2.6 Deliver project / managed service work

**Current state.** The product is **read-only** and explicitly does not
remediate (`docs/methodology/assessment-model.md:118`, `SECURITY.md:27`). It
provides `deep_link` URLs to the admin page for each finding
(`docs/report.md:144-151`), which is the intended handoff to a human operator.

**Gaps.**
- **No remediation tracking.** There is no way to record that a gap was
  remediated, by whom, or when. The `diff` command can show a gap resolved
  between two scans (`src/licenselens/diff_report.py:56-59`), but that is
  inferred from a re-scan, not tracked as work.
- **No ticket/PSA integration.** Nothing emits to a ticketing system or PSA.
  The action-plan CSV is the only machine-readable handoff, and it is not
  batch-wired (see 2.5).

### 2.7 Reassess

**Current state.** Re-running `batch` produces a new timestamped report set under
`reports/<slug>/<timestamp>/` (`docs/msp-batch.md:126-133`). The `diff` command
compares two per-tenant JSON artifacts by `check_id` and groups into new gaps,
resolved, improved, worsened, unchanged, plus confidence changes
(`src/licenselens/diff_report.py:14-79`, `docs/msp-batch.md:160-169`). A
scheduled, secret-free CI workflow runs `scan --auth oidc` daily
(`docs/msp-batch.md:57-75`, `.github/workflows/continuous-assessment.yml`).

**Gaps.**
- **`diff` is single-tenant and manual.** It takes two explicit JSON paths
  (`docs/msp-batch.md:160-169`). There is no batch-level "diff this month vs
  last month across all tenants" command, and no automatic pairing of the latest
  two runs per slug.
- **No historical trend storage.** Reports are timestamped directories; nothing
  maintains a time-series of a tenant's realized % or gap counts. Trend
  "improvement" must be reconstructed by the operator from archived JSON.
- **OIDC is not available in `batch`.** The scheduled CI workflow uses
  `scan --auth oidc` (single tenant). The `batch` command has no `--auth` flag
  (`src/licenselens/cli.py:1314-1347`), and `batch.py`'s `_AUTH_MODE_ALIASES`
  (`src/licenselens/batch.py:16-28`) does not include `oidc`. So the secret-free
  unattended path cannot drive a multi-tenant batch; batch live mode defaults to
  `client_secret` (`src/licenselens/batch.py:101`).

### 2.8 Show improvement during QBR

**Current state.** The single-tenant HTML report is a polished, offline-first
dashboard with a posture figure, capability constellation, ranked moves, and an
explore view (`docs/report.md:123-174`). `merge-reports` produces a single-file
cross-tenant dashboard with a client-side tenant switcher
(`docs/report.md:90-107`). The `diff` output can show resolved/improved checks.

**Gaps.**
- **No QBR-ready trend narrative.** There is no generated "improvement over
  time" view (e.g., realized % by month, gaps closed since last quarter) that an
  MSP can drop into a QBR deck. The `diff` is a developer-oriented check list,
  not a customer-facing trend chart.
- **No portfolio summary for the MSP's own book.** The `merge-reports` dashboard
  is tenant-switcher oriented; there is no "your whole book of business" summary
  (total exposed tenants, recurring gaps, average realized %).

### 2.9 Cross-cutting: customer isolation and report separation

**Current state.** Batch nests reports under `reports/<slug>/<timestamp>/`
(`docs/msp-batch.md:126-133`), giving per-tenant directory separation. Reports
are redacted by default (`docs/limitations.md:43`). `merge-reports` applies the
**union** of every tenant's redaction targets so a cross-tenant identifier is
scrubbed from every region (`docs/report.md:102-107`).

**Gaps.**
- **Isolation is directory-level, not enforced.** Nothing prevents an operator
  from mixing tenants in one output root, and the batch index is a single file
  listing all tenants (`src/licenselens/batch.py:200-203`). There is no
  per-tenant access control, no per-tenant encryption, and no guarantee that one
  customer's report cannot be read by another's operator.
- **Redaction is best-effort, not a boundary.** Redacted artifacts can still
  carry evidence samples, non-tenant object ids, and third-party host names
  (`docs/limitations.md:44`). JSON/ZIP reports embed `tenant_id` and evidence and
  are explicitly "sensitive" (`docs/report.md:109-121`). For an MSP, this means
  report handling is a manual discipline, not a product guarantee.

### 2.10 Cross-cutting: MSP operator ergonomics

**Current state.** The CLI is deterministic, offline-first, and has a `doctor`
preflight (`docs/cli.md:48-73`). Exit codes are documented
(`docs/cli.md:266-276`). The batch continues past a failing tenant and records
the error in the index (`src/licenselens/batch.py:175-190`,
`docs/msp-batch.md:138-142`).

**Gaps.**
- **No batch-level auth flag.** An operator must set auth per tenant in YAML or
  rely on the `client_secret` default (`src/licenselens/batch.py:101`). There is
  no `--auth` on `batch` (`src/licenselens/cli.py:1314-1347`), so switching the
  whole portfolio to a different auth mode requires editing every tenant entry.
- **No scheduling/orchestration built in.** The daily CI workflow is a GitHub
  Actions file for a single tenant (`docs/msp-batch.md:57-75`); there is no
  product-level scheduler, no retry policy beyond the Graph client's built-in
  retries (`src/licenselens/graph.py:137-183`), and no alerting when a tenant
  scan fails or a posture regresses.
- **No drift comparison across the portfolio.** `diff` is single-tenant and
  manual (see 2.7). There is no "which tenants drifted since last month" report.

---

## 3. Prioritized minimum-credible-features recommendations

The goal is to make the MSP workflow **credible**, not to build a platform.
These are the smallest set of changes that close the largest gaps. Each is
scoped to the existing CLI/report architecture.

1. **Wire `--export action-plan` into `batch`** (closes 2.5, 2.6). Emit a
   per-tenant `action-plan.csv` beside each report and a merged portfolio CSV at
   the batch root. This turns "identify gaps" into "here is the implementation
   backlog" with zero new architecture. Pointer: `src/licenselens/batch.py:139-149`
   (where reports are written) and `docs/report.md:55-75`.

2. **Add `--auth` to `batch` and accept `oidc` in `_AUTH_MODE_ALIASES`**
   (closes 2.7, 2.10). This makes the secret-free unattended path usable for a
   multi-tenant portfolio and lets an operator switch the whole book to one auth
   mode without editing YAML. Pointer: `src/licenselens/cli.py:1314-1347` and
   `src/licenselens/batch.py:16-28`.

3. **Add a batch-level `diff` that pairs the latest two runs per slug**
   (closes 2.7, 2.8). Reuse `diff_scans` (`src/licenselens/diff_report.py:14-79`)
   across the newest two timestamped JSONs per tenant and emit a portfolio
   "resolved / new / worsened" summary. This is the minimum needed to "show
   improvement during QBR" without building a trend store.

4. **Add a `priority`/`tier` key to `tenants.yaml` and surface it in the batch
   index** (closes 2.4). A single optional per-tenant field, merged from
   `defaults`, lets the index sort by customer priority before exposure count.
   Pointer: `src/licenselens/batch.py:97-119` and `docs/msp-batch.md:97-119`.

5. **Document and enforce per-tenant secret handling in the batch path**
   (closes 2.1, 2.9). At minimum, warn loudly when `client_secret` is present in
   YAML (it is already discouraged in `docs/msp-batch.md:121-124`), and add a
   `doctor`-style preflight that confirms each tenant's credential resolves
   before the batch runs. Pointer: `src/licenselens/batch.py:122-127`.

6. **Add a portfolio-level "recurring gaps" summary to `index.md`**
   (closes 2.3). Count how many tenants share each `check_id` gap and list the
   top recurring controls. This is a small aggregation over the already-collected
   per-tenant results in `run_batch` (`src/licenselens/batch.py:150-168`).

These six items are deliberately small, stay within the existing CLI/report
architecture, and collectively move the product from "per-tenant assessor" to a
credible MSP assessment-and-improvement loop without introducing a platform.

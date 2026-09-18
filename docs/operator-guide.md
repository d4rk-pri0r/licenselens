# Operator guide

This is the path to follow if you are new to LicenseLens or need to explain it to someone else.

## What LicenseLens does

LicenseLens is a local, read-only Microsoft security activation assessment.

It answers one bounded question:

> Of the security capabilities this tenant owns, which ones are being put to use, which need attention, and what evidence supports that conclusion?

It is not a hosted dashboard, a compliance certification, a replacement for Secure Score, or an autonomous remediation tool. The CLI reads permitted Microsoft data and writes report files locally. It never changes tenant configuration.

## The five-minute path

Run the offline demo first. It requires no tenant, credentials, network access, or Microsoft account:

```bash
pipx install licenselens
licenselens demo --open
```

If the browser does not open automatically:

```bash
licenselens demo -o reports
open reports/security-license-lens-report.html       # macOS
start reports\security-license-lens-report.html     # Windows
xdg-open reports/security-license-lens-report.html  # Linux
```

The demo prints an executive summary and writes three artifacts:

```text
reports/
  security-license-lens-report.html   # human report
  security-license-lens-report.json   # portable source artifact
  security-license-lens-report.md     # plain-text summary
```

Use the HTML file for the narrative. Use JSON when comparing runs or integrating with another system. Use Markdown when reviewing or attaching a concise summary.

## Read the report in this order

The report is deliberately a story. Do not start by opening every technical drawer.

1. **Where you stand** — the headline percentage and its plain-language sentence.
2. **What matters most** — the small number of actions that should change the result first.
3. **What you already own** — the capabilities behind the headline, with their status.
4. **Findings** — the evidence-backed controls that explain the actions.
5. **Technical details** — SKUs, check IDs, evaluator fields, and the full reference ledger.

The first two sections answer “what should I do?” The capability and finding sections answer “why?” The technical details answer “exactly how did the tool derive this?”

### What the headline means

`38% realized` does not mean 38% of all Microsoft security is effective. It means the numerator and denominator for the prioritized, owned capabilities met the report's defined assessed criteria. Read the sentence beside the number; it is the authoritative interpretation.

The report keeps these populations separate:

- **Owned / evaluated** — capabilities for which the scan had an entitlement and an assessment scope.
- **Met assessed criteria** — owned capabilities whose assessed criteria were met.
- **Action required** — owned capabilities with a material gap.
- **Incomplete / not assessed** — the evidence was missing, blocked, or insufficient for a conclusion.
- **Not licensed** — the capability is outside the tenant's owned entitlement; this is not a security gap.
- **Entitlement unknown** — the scan could not establish ownership; this is not treated as not licensed.

### What to do with an action

Each priority move has four useful pieces:

- **Title** — the decision or change to make.
- **Why** — the security consequence in operator language.
- **Action** — the concrete implementation step.
- **Open the admin page** — a starting point, not proof that the change is safe for this tenant.

The effort label is a rough planning bucket, not a delivery estimate. Review scope, exclusions, break-glass accounts, and change-control requirements before acting.

### How to read a finding

Expand a finding only when you need to validate or challenge a priority. Read the slots in order:

| Slot | Question it answers |
|---|---|
| Expected | What state did the check require? |
| Observed | What did the scan actually see? |
| Why it matters | Why does this matter for the owned capability? |
| Recommended action | What should the operator investigate or change? |
| Evidence | Which sources, fields, and limitations support the conclusion? |
| Admin destination | Where the operator can review the setting. |

A finding's **evaluation mode** matters. Direct evidence reads the control itself. Proxy evidence infers from a neighboring signal and is labeled. Manual evidence requires operator confirmation. Missing or failed evidence stays incomplete or unknown rather than becoming a clean pass.

## Installation choices

### macOS and Linux

The supported end-user path is pipx:

```bash
python3 --version       # Python 3.12 or newer
pipx --version
pipx install licenselens
licenselens version
```

If pipx is not installed, install it with your platform's Python package tooling, then reopen the terminal so its executable directory is on `PATH`.

### Windows

Use Python 3.12+ and pipx from PowerShell:

```powershell
py --version
py -m pip install --user pipx
pipx ensurepath
# Reopen PowerShell after ensurepath
pipx install licenselens
licenselens version
licenselens demo
```

The Python wheel includes the packaged PowerShell bridge. Government-cloud and standalone-installer limitations are documented in [Windows](windows.md).

### Contributors

Clone the repository and install the development environment:

```bash
git clone https://github.com/d4rk-pri0r/licenselens.git
cd licenselens
uv sync --extra dev
uv run licenselens demo -o /tmp/licenselens-demo
uv run pytest -q
```

The contributor environment is for tests and source changes. End users should use pipx or a built wheel.

## First live scan

Live scans require an Entra app registration with the documented read permissions and admin consent. Start with the [App registration](app-registration.md) page; do not copy a secret into chat or commit it.

Set credentials in the environment, not in a report or source file:

```bash
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
```

Preflight before scanning:

```bash
licenselens doctor --live --auth client_secret --profile basic
```

Then run the smallest useful scope:

```bash
licenselens scan \
  --live \
  --auth client_secret \
  --profile identity \
  --pack identity \
  -o reports/live-identity
```

Use `--profile full` only after the basic path works. Add endpoint, Sentinel, email, or PowerShell-backed surfaces deliberately; every backend changes the evidence and permissions involved.

### Exit codes

| Code | Meaning | Operator response |
|---|---|---|
| `0` | Scan completed without gap or partial findings | Review the report; a zero does not mean every capability was assessed. |
| `1` | Scan completed and found gap or partial results | Review the priorities and evidence. This is a usable assessment, not a tool failure. |
| `2` | Authentication, configuration, or API failure | Fix the preflight/configuration problem before interpreting the result. |

## What happens during a scan

The runtime follows this sequence:

```text
Authentication
  → entitlement collection
  → capability mapping
  → read-only evidence collection
  → deterministic evaluators
  → uncertainty policy
  → ranking and rollup
  → HTML / JSON / Markdown
```

The important boundary is between evidence and interpretation:

- Collectors read Microsoft data and record collection quality.
- Evaluators apply deterministic predicates to normalized evidence.
- The quality policy prevents proxy, partial, missing, or failed evidence from becoming false certainty.
- The report view model turns the result into customer-facing language.
- The renderer adds navigation and progressive disclosure; it does not decide the verdict.

See [Component map](component-map.md) for the file-level version of this model.

## Outputs and reassessment

Keep the JSON from each authorized scan. It is the stable input to reassessment and diffing:

```bash
licenselens diff \
  reports/before/security-license-lens-report.json \
  reports/after/security-license-lens-report.json \
  -o reports/change.md
```

The diff separates new gaps, resolved findings, improved findings, worsened findings, and unchanged findings. A before/after diff is stronger evidence than a single posture percentage because it shows whether a decision changed the measured state.

For batch assessments:

```bash
licenselens batch tenants.yaml -o reports/batch
licenselens merge-reports reports/batch -o reports/portfolio.html
```

Treat live JSON, HTML, Markdown, and ZIP artifacts as sensitive. They can contain tenant IDs, evidence, and related metadata.

## When the result looks surprising

Use this order instead of assuming the evaluator is wrong:

1. Check whether the capability is actually owned.
2. Check the finding's evaluation mode and confidence.
3. Read the limitations and collection warnings.
4. Open Technical evidence and inspect the named data sources and fields.
5. Compare the expected state with the tenant's actual scope and exclusions.
6. Re-run only after correcting the evidence or scope.
7. If the claim still looks wrong, open the matching practitioner challenge template with sanitized evidence.

Never turn “the API did not return evidence” into “the control is absent.”

## Where to go next

- [Read a report](report-guide.md) — the full report narrative and evidence model.
- [Concepts](concepts.md) — entitlement, capability, check, finding, and status vocabulary.
- [App registration](app-registration.md) — live read-only authentication.
- [CLI reference](cli.md) — every command and flag.
- [Component map](component-map.md) — how contributors trace a result through the code.
- [Methodology](methodology/assessment-model.md) — what the product may and may not claim.

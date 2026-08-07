## Purpose

Defines the first-run Monday path so a moderately skilled, results-driven operator reaches a trustworthy top card without reading developer docs end-to-end.

## ADDED Requirements

### Requirement: Demo before auth
The CLI MUST provide a demo (or equivalent default dry-run) command that produces an HTML report with a top card without live tenant credentials.

#### Scenario: Fresh install dry-run
- **WHEN** a user runs the demo/dry-run entry after install
- **THEN** an HTML report is written, mode is dry-run, and the terminal prints the HTML path

### Requirement: Quickstart auth wizard
The CLI MUST provide a quickstart flow that explains read-only posture, performs interactive sign-in (device code by default), confirms the connected organization name, and offers to run doctor and/or a live scan.

#### Scenario: Successful device code connect
- **WHEN** a user completes quickstart device code sign-in
- **THEN** the CLI displays the organization display name and prompts for next step (doctor or scan)

#### Scenario: Device code blocked by tenant policy
- **WHEN** device code authentication fails because the tenant blocks that flow
- **THEN** the CLI explains the failure in plain English and points to the app-registration / MSP path as the next verb

### Requirement: Doctor speaks English with ready-enough
Doctor MUST summarize probes with clear pass/warn/fail states and human fixes. Doctor MUST distinguish auth failure from partial permission success. A tenant that can assess identity pack signals MUST be treated as ready enough to scan even if endpoint or email permissions are missing.

#### Scenario: Identity OK, MDE 403
- **WHEN** core Graph identity reads succeed and MDE returns 403
- **THEN** doctor reports ready enough for identity (and any other succeeding packs), warns on MDE with a one-line fix, and does not hard-fail the entire preflight solely due to MDE

### Requirement: Partial card preferred to failed scan
When some collectors fail for permissions but entitlements and at least one talk pack can evaluate, scan MUST still write reports with honest error/skipped findings and a top card reflecting assessed capabilities, rather than exiting only with a stack trace and no HTML.

#### Scenario: Limited permissions live scan
- **WHEN** live scan runs with Global Reader-equivalent access sufficient for identity but not MDE
- **THEN** HTML report is produced, limitations are visible, and identity moves can still appear

### Requirement: Scan completion CTA
On successful report write for an interactive scan, the CLI MUST print the HTML path and a short screenshot CTA reminder (redact org name; share top card).

#### Scenario: Interactive live scan completes
- **WHEN** `scan --live` finishes writing reports
- **THEN** terminal output includes organization-oriented summary (% realized or move count when available), the HTML path, and CTA guidance

### Requirement: Hero install documentation
Project docs MUST document one hero install path (`pipx install licenselens` once published) and one escape hatch (container image), with demo as the first command after install.

#### Scenario: README first paint
- **WHEN** a user opens the README hero section
- **THEN** they see the hallway line, a top-card screenshot or sample link, the hero install, and the demo command before deep architecture content

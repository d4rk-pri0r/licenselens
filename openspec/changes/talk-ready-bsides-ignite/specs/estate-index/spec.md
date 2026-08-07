## Purpose

Defines the multi-tenant batch index MSPs use on Friday triage — estate-level sort keys over the same per-tenant top card artifact.

## ADDED Requirements

### Requirement: Estate index summarizes each tenant
A batch run MUST write an estate index (Markdown at minimum) listing each tenant slug with realized percentage (when computable), exposed count, top-move count or worst move title, and failure state if the tenant scan did not complete.

#### Scenario: Mixed estate
- **WHEN** batch runs three tenants — two success, one auth failure
- **THEN** the index includes rows for all three and marks the failed tenant with an error summary without aborting the whole batch

### Requirement: Default triage sort key
The index SHOULD order tenants with exposed findings first, then by lowest realized percentage. If stable sort documentation prefers generating an unsorted table plus explicit sort guidance, the documented Friday ritual MUST state EXPOSED-first then lowest realized as the operator sort.

#### Scenario: Operator opens index
- **WHEN** an MSP engineer opens index.md after batch
- **THEN** they can identify the most exposed / least realized tenants within one screen of summary content

### Requirement: Same card per tenant
Batch MUST continue to write per-tenant HTML reports that use the same top-card contract as single-tenant scan (no simplified MSP-only card that drops owner-voice moves).

#### Scenario: QBR reuse
- **WHEN** an engineer opens a single tenant HTML from a batch output folder
- **THEN** the top card matches the single-scan card structure (own/working, moves, seal)

### Requirement: MSP documentation chapter
Docs MUST include an MSP chapter covering app-only auth, tenants.yaml example, Friday batch command, monthly diff usage, and the rule that the tool is vendor-neutral OSS.

#### Scenario: MSP reader path
- **WHEN** an MSP engineer follows the MSP chapter from a cold start with an existing app registration
- **THEN** they can run batch and locate index.md plus per-tenant HTML without reading engine architecture docs

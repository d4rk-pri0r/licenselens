## Purpose

Defines when a finding is classified EXPOSED (actively weaker than default or purposefully open) versus ordinary entitlement-gated gap or partial.

## ADDED Requirements

### Requirement: Exposure is a second axis
The system SHALL support an exposure classification distinct from realization status. Ordinary unused-but-owned capabilities remain gap or partial. Only configured-dangerously cases MAY be exposed.

#### Scenario: PIM unused is not exposed by default
- **WHEN** PIM is licensed but standing admins remain and no worse-than-default sign-in path is detected
- **THEN** the PIM finding is gap or partial with exposure_class none (not exposed)

### Requirement: EXPOSED — legacy authentication broadly allowed
When Conditional Access (or equivalent entitlement) is owned, the system MUST classify legacy authentication as exposed if no enabled control blocks legacy authentication for all users (or documented tenant-wide equivalent), subject to the evaluator rubric. Report-only legacy blocks MUST be partial, not exposed.

#### Scenario: No legacy block policy
- **WHEN** the tenant owns Conditional Access and has no enabled legacy-auth block covering all users
- **THEN** a finding is produced with exposed classification and owner-voice title about outdated sign-in methods still allowed

#### Scenario: Report-only legacy block
- **WHEN** a legacy-auth block exists only in report-only mode
- **THEN** the finding is partial and not exposed

### Requirement: EXPOSED — MFA-less privileged admin path
When MFA can be required via owned Conditional Access (or equivalent), the system MUST classify as exposed if Global Administrator (and/or the defined tier-0 privileged set) can sign in without an enforced MFA grant on enabled policy, after applying the documented break-glass exclusion rules.

#### Scenario: Global Admin without enforced MFA
- **WHEN** privileged roles including Global Administrator lack enabled CA MFA enforcement
- **THEN** a finding is produced with exposed classification and owner-voice title about top admin accounts signing in without extra proof

#### Scenario: Admin MFA enforced, user MFA missing
- **WHEN** MFA is enforced for admins but not for all users
- **THEN** any user-coverage gap is ordinary gap or partial and MUST NOT alone create the MFA-less GA exposed finding

### Requirement: v1 exposure cap
For talk-ready v1, only the legacy-auth and MFA-less privileged-admin classes MAY set exposure_class to exposed. Additional exposure classes MUST NOT ship without an explicit spec change.

#### Scenario: Other dangerous misconfigs
- **WHEN** a check detects a serious but non-listed condition
- **THEN** it uses gap/partial/error without exposed classification unless it matches one of the two v1 classes

### Requirement: Card and index consume exposure
Exposed findings MUST surface on the report top card chip and on the estate index Exposed column when batching.

#### Scenario: Batch tenant with exposure
- **WHEN** batch completes for a tenant with one exposed finding
- **THEN** that tenant's index row shows a non-zero Exposed count

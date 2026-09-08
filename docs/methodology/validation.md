# Validation

This document defines how LicenseLens checks are validated and how the project
records real-tenant and practitioner validation without inventing numbers.

## What validation means here

A check's unit tests passing is **necessary but not sufficient** for it to be
considered valid. A check is "validated" only when, at minimum:

- its security claim is precisely defined and the evidence source actually
  supports it;
- its evaluator is deterministic;
- positive, negative, missing-data, and API-error cases are tested;
- its terminology does not overstate what was measured;
- its entitlement mapping is sourced;
- a Microsoft/SCuBA reference documents the desired state;
- its limitations are visible.

Flagship checks carry an even higher bar (intent, entitlement mapping, real
evidence path, determinism, all test classes, an authoritative reference, a
human explanation, explicit limitations, and proof the displayed finding does
not overstate the evidence). See the project quality-gate checklist and the
maturity dashboard for the per-flagship status.

## Validate Microsoft claims against primary documentation

Every security or licensing assertion is checked against authoritative Microsoft
documentation (Microsoft Learn, Microsoft licensing docs, product docs, CISA/
SCuBA, recognized standards) rather than inferred or guessed. Passing unit tests
are not treated as proof a security assertion is semantically correct. Where the
documentation cannot support a conclusion, LicenseLens narrows or qualifies the
claim instead of forcing the evidence to fit.

## Practitioner validation process

Reviewers can challenge any check. The project keeps:

- issue templates for false positives, false negatives, Microsoft API
  inconsistency, licensing corrections, methodology challenges, and new edge
  cases;
- a documented challenger workflow (what to include in an issue, how to submit
  edge cases, how to propose changed semantics, how to add tenant-safe test
  fixtures, how to dispute a licensing mapping);

Reviewer disagreement is treated as useful evidence, recorded, and folded back
into the checks or into a documented limitation.

## Real-tenant validation recording

When a controlled or real tenant is validated, the framework permits recording a
sanitized result set:

```text
tenant profile
licenses
observed findings
human validation
false positives
false negatives
manual confirmations
changed classifications
API limitations
unexpected edge cases
```

From these it computes summary metrics. Unique-check breadth (how many distinct
checks have been reviewed) is separate from per-assessment observations (the
same check in two runs is two observations). The rejection share is
`rejected / (confirmed + rejected)` observations; with no adjudicated
observations it is unmeasured, never zero. Unresolved annotations are excluded.
This share is **not** a statistical false-positive rate.

```text
total evaluated findings
human-confirmed findings (unique checks)
rejected findings (unique checks)
confirmed / rejected observations (per run)
rejected share (or unmeasured)
reclassified / manual-only / unknown findings
false-negative discoveries
```

**No validation numbers are invented.** Integer counts default to zero;
`rejected_share` defaults to unmeasured until a confirmed or rejected
observation is recorded. Until a tenant run is actually recorded, the maturity
dashboard reports "no validated tenant runs" rather than a made-up figure.

## Validation status recording

Every flagship check can carry a practitioner-validation status so the project
tracks, honestly, exactly which checks have been reviewed by whom and with what
outcome. A check is not removed from the "needs validation" set merely because
its tests pass.

# Scoring

This document defines the semantics of every aggregate number in LicenseLens.
The central rule is: **no aggregate score may imply "this tenant is X% secure."**

## The posture figure

The report's headline posture percentage is:

```text
% realized = fully_working / you_own
```

where, for the sets of checks in the priority packs being scanned:

- `you_own` = number of owned capabilities that have at least one related
  check in scope;
- `fully_working` = number of those capabilities for which all related checks
  are `ok`;
- `needs_attention` = a capability with any `gap` related check;
- `partly_set_up` = a capability with only partial/error/skipped related checks
  (proxy-capped checks count as partial);
- `not_licensed` = capabilities referenced by in-scope checks that the tenant
  does **not** own (informational only, excluded from `you_own`).

The number therefore reads as:

> Of the security controls associated with the entitlements and assessment
> scope that LicenseLens could evaluate, X% met the defined activation
> criteria.

It is **not** "the tenant is X% secure." It is scoped in three ways that are
always true of the figure:

1. **Entitlement-scoped** — only capabilities the tenant owns are counted
   (`not_licensed` is excluded, never penalized).
2. **Assessment-scope-scoped** — only checks in the priority packs being
   scanned contribute.
3. **Evaluation-limited** — only capabilities with at least one evaluated
   related check count. A capability with zero in-scope evidence is not counted
   as either working or failing.

The model exposes the denominator and both sides of the ratio
(`you_own`, `fully_working`, `needs_attention`, `partly_set_up`,
`not_licensed`) so the figure can never hide what it was computed from.
See the `realized_sentence` in the model for the human rendering of the same
ratio.

## What the score never does

- It never penalizes a customer for capabilities they do not own
  (`not_licensed` is informational).
- It never rewards a customer for checks that were never evaluated.
- It never counts `error`, `skipped`, or `unknown` as either clean or failed;
  those land in `partly_set_up` and are surfaced as limitations, not built into
  a pass/fail ratio.
- It never conflates proxy or manual evidence with direct proof (those are
  capped/downgraded first by the quality policy).
- It is deterministic: identical normalized evidence always yields the same
  percentage.

## Determinism under missing evidence

Aggregate numbers are designed so that **missing evidence cannot silently
change a score toward either extreme**.

- A capability that has **no in-scope findings at all** is entirely excluded
  from both the numerator (`fully_working`) and the denominator (`you_own`).
  It never contributes as fully working, as failing, or as anything else—so an
  uncollected surface cannot inflate the ratio or award credit for an
  unevaluated check.
- A capability whose controls could not be read produces an explicit
  `error`/`partial` finding, which counts as `partly_set_up` and surfaces a
  visible limitation—never as a clean pass and never as a silent gap.
- Only `gap` drives `needs_attention`; everything else non-`ok` lands in
  `partly_set_up`, so a missing or failed collection cannot push a capability
  into the failing bucket.

These rules guarantee that *removing evidence never makes a tenant look more
secure*, and that *failing to collect evidence never makes a tenant look
insecure without an explicit, visible reason*. Regression tests assert that the
ratio cannot drift because of missing evidence.

## Statuses vs. the score

The full status set (see [uncertainty](./uncertainty.md)) distinguishes `gap`,
`partial`, `ok`, `not_licensed`, `error`, and `skipped`. Only `gap` is a hard
failure for the score's `needs_attention`; every other non-`ok` status is
`partly_set_up`, and `not_licensed` is outside the score entirely. This is what
keeps an unowned capability from being a black mark and an unverified result
from being counted as either good or bad.

## Exit codes are not a score

The CLI exit code is a CI signal, not a security grade:

| Code | Meaning |
|---|---|
| 0 | Scan completed with no gap/partial findings |
| 1 | Completed with gap or partial findings (work to do) |
| 2 | Auth / configuration / API error |

Exit `2` (failure) must never be confused with "the tenant failed a security
check."

## Documented, tested

The scoring semantics above are sealed by tests (`test_catalog_entitlements`,
`test_report_manifest`, golden-tenant and dry-run matrix tests). Any change to
the ratio definition must update this document and add a regression test before
it lands. The headline metric the project tracks for itself is the share of
flagship assessments meeting the full trust standard, **not** the number of
checks. See the project maturity dashboard.

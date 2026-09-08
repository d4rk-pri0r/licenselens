# Scoring

This document defines the semantics of every aggregate number in LicenseLens.
The central rule is: **no aggregate score may imply "this tenant is X% secure."**

## The posture figure

The report's headline is a fraction first, a percentage second:

```text
% realized = fully_working / you_own
```

rendered as *"N of D in-scope capabilities met all assessed criteria (P%)."*
where, for the sets of checks in the priority packs being scanned:

- `you_own` = owned capabilities with at least one related in-scope check
  **whose related findings are not all error/skipped** — this is the
  denominator, and it is the same denominator the operational distribution
  bar draws;
- `fully_working` = those capabilities for which every related check is `ok`;
- `needs_attention` = a capability with any `gap` related check;
- `partly_set_up` = a capability with **observed** partial implementation —
  at least one `partial` finding and no `gap` (proxy-capped checks count as
  partial). Error and skipped findings never land here;
- `assessment_incomplete` = a capability whose non-missing findings are all
  `error`/`skipped` (an unreadable or pending assessment). It is visible in
  the report and counted separately, and it is **excluded from `you_own`** so
  an incomplete assessment can neither pass nor silently vanish from a
  percentage that then looks complete;
- `not_licensed` = capabilities referenced by in-scope checks that the tenant
  does **not** own and whose entitlement is not unknown (informational only,
  excluded from `you_own` and from the distribution bar);
- `entitlement_unknown` = capabilities referenced by in-scope checks whose
  entitlement could not be determined (e.g. Azure consumption capabilities
  with no readable pricing surface). Counted separately — **never** folded
  into `not_licensed`, because "we could not determine" is not "you do not
  own it."

The number therefore reads as:

> 3 of 8 in-scope capabilities met all assessed criteria (38%).

It is **not** "the tenant is 38% secure," not a license-value or ROI figure,
not a compliance score, and not a percentage of "security controls" — the
unit is *capabilities*, and the sentence says so.

It is scoped in three ways that are always true of the figure:

1. **Entitlement-scoped** — only capabilities the tenant owns are counted
   (`not_licensed` and `entitlement_unknown` are excluded, never penalized,
   and shown as a separate caption line rather than inside the operational
   distribution bar).
2. **Assessment-scope-scoped** — only checks in the priority packs being
   scanned contribute.
3. **Evaluation-limited** — only capabilities with at least one evaluated
   related check count, and only assessed findings enter the denominator. A
   capability with zero in-scope evidence is not counted as either working
   or failing; a capability whose only findings are `error`/`skipped` is
   `assessment_incomplete`, not part of the ratio.

The model exposes the denominator and both sides of the ratio
(`you_own`, `fully_working`, `needs_attention`, `partly_set_up`,
`assessment_incomplete`, `not_licensed`, `entitlement_unknown`) so the figure
can never hide what it was computed from. See the `realized_sentence` in the
model for the human rendering of the same ratio.

## What the score never does

- It never penalizes a customer for capabilities they do not own
  (`not_licensed` is informational) or could not be resolved
  (`entitlement_unknown` is a separate count).
- It never rewards a customer for checks that were never evaluated.
- It never counts `error`, `skipped`, or unknown entitlements as either clean
  or failed; errors and skips land in `assessment_incomplete` (outside the
  ratio), unknown entitlements in `entitlement_unknown` (outside the ratio).
- It never presents an observed partial implementation
  (`partly_set_up`) as the same thing as an unreadable assessment
  (`assessment_incomplete`) — one means "we saw it half-done," the other
  means "we could not look."
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
  `error`/`skipped` finding, which counts as `assessment_incomplete` and
  surfaces as a visible, named category outside the ratio—never as a clean
  pass, never as a silent gap, and never as `partly_set_up`.
- Only `gap` drives `needs_attention`; only `partial` (an observed partial)
  drives `partly_set_up`, so a missing or failed collection cannot push a
  capability into the failing bucket or dress an unreadable one up as
  half-implemented.

These rules guarantee that *removing evidence never makes a tenant look more
secure*, and that *failing to collect evidence never makes a tenant look
insecure without an explicit, visible reason*. Regression tests assert that the
ratio cannot drift because of missing evidence.

## Detection-realization numbers

The detection matrix keeps three states per cell instead of a forced binary:

- **Arriving?** is `Yes`/`No` only when the ingestion check actually produced
  evidence for the capability; when the ingestion finding is missing, errored,
  skipped, or carries no capability evidence, the cell reads
  **Not assessed** — missing evidence is never displayed as "No."
- **Live rules (when assessed)** is a count only when the parity finding was
  assessed (`ok`/`gap`/`partial`) and the table is ingesting; otherwise it
  reads **Not assessed**. A table that is ingesting but listed as unwatched
  reports `0`; a table merely absent from the unwatched list reports a
  bounded `1` marked `parity-not-unwatched` — the parity evidence carries no
  per-table live-rule counts, so a larger count is never invented from the
  mere existence of the finding.

## Statuses vs. the score

The full status set (see [uncertainty](./uncertainty.md)) distinguishes `gap`,
`partial`, `ok`, `not_licensed`, `error`, and `skipped`. Only `gap` is a hard
failure for the score's `needs_attention`; only an observed `partial` makes
`partly_set_up`; `error`/`skipped` make `assessment_incomplete`; and
`not_licensed` plus unknown entitlements are outside the score entirely. This
is what keeps an unowned capability from being a black mark and an unverified
result from being counted as either good or bad.

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

The scoring semantics above are sealed by tests (`test_rollup`,
`test_uncertainty_contract`, `test_report_viewmodel`, golden-tenant and
dry-run matrix tests). Any change to the ratio definition must update this
document and add a regression test before it lands. The headline metric the
project tracks for itself is the share of flagship assessments meeting the
full trust standard, **not** the number of checks. See the project maturity
dashboard.

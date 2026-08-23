# Uncertainty and failure semantics

LicenseLens prefers uncertainty over fabricated certainty. This document defines
the status set, the distinction between "the API failed" and "the tenant is
insecure," and the rules for partial results.

## Status set

Whenever a value cleanly maps, LicenseLens uses these statuses (a smallest
set that represents semantics without collapsing distinct situations):

| Status | Meaning |
|---|---|
| `gap` | Licensed capability is off, unconfigured, or left at default; evaluated evidence supports failure. |
| `partial` | Partially configured or only partially verifiable; some of the expected control is missing or some evidence is missing. |
| `ok` | The expected control is in place, supported by sufficient evaluated evidence. |
| `not_licensed` / `not_entitled` | The capability is outside what the tenant owns; informational, never a false gap. |
| `manual` | Operator confirmation is required; not auto-passed. |
| `unknown` / `insufficient_evidence` | The evaluator could not determine the state with the available evidence. |
| `not_applicable` | The control does not apply to the tenant's configuration scope. |
| `error` | The collector/evaluator failed; surfaced per-check, never silent. |

The software serializes the closest implemented equivalent and always keeps
`gap`, `partial`, `ok`, `not_licensed`, `error`, and `skipped` distinct.

## The cardinal distinctions

The product is engineered so the following are separate and are never collapsed:

```text
API failure            ≠  security failure
missing permission     ≠  security gap
unsupported Microsoft API ≠  security gap
partial result         ≠  complete assessment
absence of evidence    ≠  evidence of absence
```

- An **API failure** produces an `error`/`partial` finding that says the data
  could not be read—it is not counted as a security gap.
- A **missing permission** produces an explicit `partial` with a limitation
  explaining the permission, not a silent empty success or a fabricated gap.
- An **unsupported surface** (e.g., a control with no read API in this tool) is
  disclosed as such and never becomes a gap.
- A **partial result** degrades confidence, identifies the limitation, and is
  handled correctly by the aggregate score (counted under `partly_set_up`,
  never built into pass/fail).
- **Absence of evidence** never becomes evidence of absence: a check that could
  not run or could not verify the true predicate reports the reason instead of a
  clean pass or a gap.

## Confidence

Every finding carries a confidence (`high`, `medium`, or `low`) that reflects
how strongly the normalized evidence supports the conclusion:

- Direct evidence from the preferred backend → high (unless truncated).
- Proxy evidence → low (and capped at `partial` under strict proxy policy).
- Manual evidence → reflects operator confirmation.
- Truncated/sampled evidence → downgraded from high to medium, and never yields
  a clean `ok` that hides the sample.

Confidence is reported alongside the status and evidence type; a user inspecting
a finding can see both *what* was concluded and *how certain* the evidence makes
it.

## Partial-result handling

When collection returns only part of the data:

1. the finding records the truncation/sampling marker in evidence;
2. confidence is degraded;
3. any would-be `ok` is capped to `partial`;
4. a limitation names the truncation;
5. aggregate scores treat the capability as `partly_set_up`, so the missing data
   cannot silently shift the percentage toward pass or fail.

## Fail-safe defaults

Defaults are conservative:

- If the preferred backend is unavailable, a dynamic check falls back to a
  labeled proxy only, or reports `partial`/`unknown` rather than inventing a
  verdict.
- If evidence is missing altogether, the finding is `partial`/`error` with the
  reason, never a silent drop and never a fabricated pass/gap.
- No structural limitation is hidden behind a score; limitations and data
  sources are explicit on every affected finding.

## Documented, tested

These semantics are enforced by the quality policy
(`apply_quality_policy`) and asserted by tests that exercise failure,
permission, truncation, and empty-data cases for the evaluators. The goal is
that a skeptical practitioner reading a finding can tell exactly which of the
above situations produced it—because the finding says so.

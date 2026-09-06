# Evidence model

This document defines what counts as evidence, how it is normalized, how its
type is classified, and how a finding exposes a traceable path back to the raw
Microsoft object or API result that produced it.

## Evidence types

Every material finding carries an assessment type from this set. The type is
derived from *what the evidence actually proves*, never from intent:

| Type | Meaning | How it is recognized in the product |
|---|---|---|
| DIRECT | The control itself was read from the preferred backend. | Check `evaluation_mode = direct`; finding data source names the governing API. |
| PROXY | A labeled neighboring signal was used because the direct read was unavailable. | `evidence.proxy = true` and/or source contains `secureScore`; capped at partial / low confidence. |
| MANUAL | Operator confirmation is required. | Check `evaluation_mode = manual`; never auto-passes. |
| UNKNOWN | The evidence is insufficient to support any verdict. | Finding is `partial`/`error`/`skipped` with an explicit limitation. |
| UNSUPPORTED | The product states it cannot conclude this with current data/APIs. | Explicitly rejected capability/limit; check may be disabled or labeled unsupported. |

A dynamic check (`direct_with_proxy_fallback`) serializes the *observed* mode
(`direct` or `proxy`) on each finding, so the report always discloses which
path actually produced the result.

## The evidence path (traceability)

Every material finding supports a traceable path:

```text
ENTITLEMENT
    ↓
MICROSOFT PRODUCT / SKU
    ↓
SECURITY CAPABILITY
    ↓
REQUIRED / EXPECTED IMPLEMENTATION
    ↓
OBSERVED MICROSOFT OBJECT OR API RESULT
    ↓
NORMALIZED EVIDENCE
    ↓
DETERMINISTIC EVALUATION
    ↓
FINDING
    ↓
CONFIDENCE / EVIDENCE TYPE
    ↓
LIMITATION
    ↓
MICROSOFT / SCuBA / RELEVANT REFERENCE
```

A technically sophisticated user examining a finding can determine:

- what was queried (the collector and data source names);
- what was found (the normalized evidence, raw object counts/samples);
- what predicate evaluated it (the evaluator's deterministic logic);
- why the result received its status (the finding's summary + limitation);
- whether the evidence was direct or inferred (`evaluation_mode`, `proxy`);
- whether any data was missing (truncation/partial markers);
- where the security recommendation originates (the Microsoft/SCuBA reference).

This "show me why" path is exposed in the report's evidence view and, at the
model level, in each finding's `evidence`, `data_sources`, `confidence`,
`evaluation_mode`, and `limitations` fields.

## Normalization

Raw Microsoft API responses are reduced to a stable, versioned shape before
they reach an evaluator. Normalization:

- keeps raw identifiers and representative object samples so evidence stays
  inspectable;
- stores counts and truncated/paged flags so evaluators know when a number is
  a sample rather than the population;
- attaches the collector and data-source name so provenance is retained.

Normalized evidence is the input to the deterministic evaluator. The evaluator
never reaches back into raw HTTP; it reasons only over normalized evidence.

## Sampling and truncation

Several collectors read bounded samples (sign-in lookbacks, MDE machine
inventory, Intune managed devices). When a sample is truncated:

- the finding records a `truncated` / `truncated_sample` marker in evidence;
- confidence is downgraded;
- an `ok` result is capped to `partial` because the population could not be
  fully observed;
- a limitation names the truncation explicitly.

The product never presents a truncated sample as the complete population.

## Absence of evidence is not evidence of absence

If a collector returns nothing because it could not run (permission denied, API
failure, unsupported surface), LicenseLens surfaces an `error`/`partial`
finding explaining *why*, rather than a clean pass or a gap. If a check cannot
evaluate the true predicate from the evidence available, it reports
`partial`/`unknown` with the reason.

## Source references

Every material recommendation and entitlement mapping carries a documented
reference (Microsoft Learn, Microsoft licensing docs, SCuBA, or recognized
standards) with its URL and, where recorded, retrieval/verification date. See
[entitlement-model](./entitlement-model.md#source-of-truth-model) for the
machine-readable metadata shape and the prohibition on LLM-generated or
community blog facts becoming authoritative product logic.

## Detection realization: telemetry and rule parity

When a Sentinel workspace is in scope, the report includes a detection-realization
matrix. It compares owned-capability core tables from the telemetry catalog
against seven-day Log Analytics Usage, and against table references extracted
from enabled scheduled/NRT analytics rules (plus XDR custom detections when
collected).

**Measured**

- Whether expected core tables arrived in the last seven days (`rows > 0` or
  `total_mb > 0` in query mode; table existence only on the ARM tables-list
  fallback).
- Whether a live analytics rule queries each ingesting core table (`watched_by`).
- Dead rules: enabled rules whose table refs are not ingesting. Parsers
  (`_Im_`, ASIM) are indeterminate and are never counted dead.

**Not measured**

- Detection effectiveness, tuning quality, alert fidelity, or time-to-respond.
- Content-hub completeness or multi-workspace estates (one
  `--workspace-resource-id` per scan).
- Per-connector collection health beyond Usage `DataType` volume.

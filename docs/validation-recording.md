# Validation recording

This page documents how an MSP or consultant records a **sanitized** real-tenant
(or controlled-lab) validation run, and how LicenseLens turns those records into
honest summary metrics.

## The hard rule: no invented numbers

**No validation numbers are invented.** Every metric defaults to **zero** until a
real, human-confirmed validation run is actually recorded. Until a tenant run is
recorded, the framework reports "no validated tenant runs" rather than a made-up
figure. The summary metrics are derived purely from recorded check_ids — they are
never guessed, extrapolated, or seeded with LLM judgment.

## Sensitivity rule

A validation record is **sanitized by construction**. Never commit:

- real tenant ids or tenant display names;
- user principal names (UPNs) or any personal data;
- client secrets, tokens, or credentials;
- unredacted live reports or raw API responses.

Only coarse, non-identifying labels belong in a record — for example a tenant
profile of `"m365-e5"` and a license summary of `["E5", "Entra ID P2"]`. If a
record would reveal who the customer is, redact it first.

## JSON schema example

A `TenantValidationRecord` serializes to JSON like this:

```json
{
  "record_id": "val-2026-08-23-001",
  "tenant_profile": "m365-e5",
  "license_summary": ["E5", "Entra ID P2"],
  "scanned_at": "2026-08-23T14:30:00Z",
  "reviewer": "alice@consultancy.example",
  "method": "real-customer-consented",
  "confirmed_findings": ["id-ca-priv-gaps", "mfa-enabled"],
  "rejected_findings": ["pur-dlp-not-enforced"],
  "reclassified_findings": [],
  "manual_only_findings": ["mdo-p2-policies-default"],
  "unknown_findings": [],
  "false_negative_discoveries": ["sentinel-workspace-missing"],
  "api_limitations": ["sign-in inventory truncated"],
  "unexpected_edge_cases": ["guest-only tenant with no owned SKUs"],
  "raw_finding_count": 42
}
```

Every field is optional and defaults to an empty/zero value when absent, so a
minimal record is just `{}`. A check_id may appear in **at most one** outcome
category per record — a check cannot be both `confirmed` and `rejected` in the
same run. The framework rejects such overlap with a `ValueError` (fail-closed,
deterministic).

## Recording workflow

1. **Run the scan** against a real tenant (or a controlled lab) and produce the
   findings artifact.
2. **Redact** the artifact: strip tenant ids, UPNs, secrets, and any unredacted
   live report content. Keep only coarse profile/license labels.
3. **Human-confirm** each finding against the actual tenant state (portal,
   PowerShell, or a trusted source). Classify every evaluated finding into
   exactly one bucket:
   - `confirmed_findings` — the tool's finding is true;
   - `rejected_findings` — a false positive;
   - `reclassified_findings` — the classification changed;
   - `manual_only_findings` — only verifiable by hand;
   - `unknown_findings` — could not be determined.
4. **Record gaps the tool missed** in `false_negative_discoveries`, and note any
   `api_limitations` or `unexpected_edge_cases`.
5. **Set `raw_finding_count`** to the total number of findings evaluated in the
   run.
6. **Commit the sanitized record** (e.g. under a `validation/` directory) so the
   summary metrics can be computed from real data.

## Summary metrics

From the recorded records, LicenseLens computes two kinds of count that must
not be mixed, plus a rejection share that is unmeasured until something has
been adjudicated:

| Metric | Meaning |
|--------|---------|
| `total_evaluated_findings` | sum of `raw_finding_count` across distinct records |
| `human_confirmed_findings` | unique-check breadth: distinct confirmed check_ids |
| `rejected_findings` | unique-check breadth: distinct rejected check_ids |
| `reclassified_findings` | distinct reclassified check_ids |
| `manual_only_findings` | distinct manual-only check_ids |
| `unknown_findings` | distinct unknown check_ids |
| `false_negative_discoveries` | distinct false-negative check_ids |
| `unique_checks_reviewed` | distinct check_ids with a confirmed or rejected annotation |
| `confirmed_observations` | per-run confirmed (check, record) pairs |
| `rejected_observations` | per-run rejected (check, record) pairs |
| `adjudicated_observations` | confirmed + rejected observations |
| `rejected_share` | `rejected_observations / adjudicated_observations`, or unmeasured (`null`) when nothing has been adjudicated |
| `false_positive_rate` | **alias of `rejected_share`**, kept so older dashboard consumers do not break. This is **not** a statistical false-positive rate (that would need a ground-truth negative denominator and a sampling design these records do not contain) |
| `validated_tenant_runs` | distinct recorded runs (`record_id` de-duplicated) |
| `duplicate_records_ignored` | later copies of the same `record_id` |

All integer counts start at zero. `rejected_share` / `false_positive_rate`
start as unmeasured, never as `0.0`. Unresolved annotations (unknown,
reclassified, manual-only) are excluded from the share. Two rejected and zero
confirmed observations is 100%, not zero; two rejected and one confirmed is
approximately 66.7%.

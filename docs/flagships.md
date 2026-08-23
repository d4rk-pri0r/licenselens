# Flagship quality gate

A flagship check is the checks LicenseLens may demonstrate publicly
(product-maturity goal §5 / §25). A flagship is **release-ready** only when it
satisfies the full trust standard below. This document records the gate, how it
is enforced in the repository, and the per-flagship status tracked by the
maturity dashboard.

## What makes a flagship

A flagship must satisfy a substantially higher standard than ordinary catalog
coverage. Every flagship is registered in `catalog/flagships.yaml` with:

- `check_id` and `security_intent` (the documented security assertion);
- `entitlement` (the capability/license it depends on);
- `evidence_source` (the API/backend + assessment type);
- `assessment_type` (`direct` or `dynamic` — never `proxy`/`manual`);
- the source-of-truth reference fields `source_url` / `source_type` (§12);
- a `status` (`draft` until an independent review flips it to `validated`).

The flagship set covers the strongest, most demonstrable areas across major
Microsoft security capabilities: Entra ID, Conditional Access,
phishing-resistant MFA, PIM, Identity Protection, Defender for Endpoint,
Defender for Office 365, Intune, Sentinel, Purview, and email authentication.

## The 18-point release gate (§25)

A flagship check is release-ready only when **all** of these hold:

- [ ] 1. Entitlement mapping has authoritative sourcing (backed by the §12
      source fields / licensing-audit reference).
- [ ] 2. Security claim is precisely defined (the `security_intent` states
      exactly what is being asserted).
- [ ] 3. Evidence source is documented (the API/backend is named).
- [ ] 4. Evidence is sufficient for the claim (the API actually supports the
      conclusion; never forced to support it).
- [ ] 5. Evaluator is deterministic (same normalized evidence → same result).
- [ ] 6. Positive case is tested.
- [ ] 7. Negative case is tested.
- [ ] 8. Missing evidence is tested.
- [ ] 9. API failure is tested.
- [ ] 10. Permission failure is tested.
- [ ] 11. Pagination/truncation is handled where applicable.
- [ ] 12. Licensing edge cases are addressed (denominator rules applied).
- [ ] 13. Finding terminology does not overclaim (no "healthy"/"coverage"
      unless the evidence supports it).
- [ ] 14. Limitations are displayed on the finding.
- [ ] 15. Report evidence is inspectable (data sources, raw observations).
- [ ] 16. Microsoft documentation is referenced (non-empty `references`).
- [ ] 17. No LLM is required for the verdict (deterministic evaluator).
- [ ] 18. Practitioner validation status can be recorded (§13/§14 framework).

## How each item is enforced

| Item | Enforcement in the repository |
|---|---|
| 1, 2, 3 | `catalog/flagships.yaml` required fields; `scripts/validate_flagship_meta.py` fails closed if any is missing. |
| 4 | Semantic audit (`audit/check-semantic-audit.md`) grounds each claim in the actual evaluator/API; the audit is verified against code. |
| 5 | All evaluators are pure functions of normalized evidence; determinism is locked by golden-tenant and dry-run matrix tests. |
| 6–11 | `tests/` per-evaluator suites exercise positive/negative/missing/error/truncation cases (identity, endpoint, sentinel, exchange, etc.). |
| 12 | Denominator rules (§6) are enforced in the MDE/Intune evaluators and validated by tests. |
| 13 | §7 language audit removed overclaiming terminology; evaluator tests assert no "looks healthy"/fabricated "coverage" claims. |
| 14 | Findings carry `limitations`; the evidence view renders them. |
| 15 | Findings expose `data_sources`, `evidence`, `confidence`, `evaluation_mode`, `references`. |
| 16 | Every flagship has non-empty `references` (Microsoft Learn). |
| 17 | No LLM appears in the verdict path; the conference answer is "deterministic and evidence is inspectable." |
| 18 | `docs/practitioner-validation.md` + the §14 validation framework record review status (defaults to zero until real review). |

## Status tracking

The maturity dashboard (`scripts/maturity_dashboard.py`) reports the headline —
the share of flagship assessments meeting the full trust standard — plus
per-flagship `status`. A flagship starts `draft`; it is flipped to `validated`
only when an independent practitioner review confirms the 18-point gate and the
record is captured through the §14 validation framework. Every metric defaults
to zero / honest until real validation is recorded — no invented numbers.

## No flagship may rely on a fragile heuristic

A flagship must not depend on a poorly justified heuristic without explicitly
identifying it. Where a heuristic is unavoidable (for example, an admin-role
count threshold), the finding must carry a limitation naming it, never present
it as proven fact, and be capped appropriately. Checks that cannot meet the
direct-evidence bar are not flagships.

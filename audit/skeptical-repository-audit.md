# Skeptical repository audit (vibe-code resistance gate)

This is the repository's own defense-in-depth review from the perspective of a
skeptical senior security engineer (product-maturity goal §24). Every question
a skeptic would ask has a concrete answer in code, documentation, tests,
product behavior, or an explicit limitation. If an answer is "we have not done
X yet," it is stated plainly.

The engineering principle under review:

> The authors know exactly what the evidence proves, what it does not prove,
> and have engineered the product accordingly.

## The 16 questions, answered

### 1. Who validated these checks?

- **Flagship checks** are enumerated in `catalog/flagships.yaml` and carry a
  `status: draft` until independent review flips them to `validated`. The
  maturity dashboard tracks the share meeting the full trust standard.
- The **practitioner validation process** (`docs/practitioner-validation.md`,
  issue templates under `.github/ISSUE_TEMPLATE/`) lets reviewers record false
  positives, false negatives, API inconsistencies, licensing corrections,
  methodology challenges, and edge cases. Real-tenant metrics default to **zero**
  until genuinely recorded (`src/licenselens/validation.py`).
- Honest answer: **no real-tenant falsification has been recorded yet** — the
  framework and dashboard report that state instead of inventing numbers.

### 2. Why does this API prove that conclusion?

- Every check names its collector and the API/backend it reads in the generated
  reference (`docs/reference/checks.md`) and exposes its `data_sources` on the
  finding.
- The methodology (`docs/methodology/evidence-model.md`) defines what each
  assessment type (direct/proxy/manual/unsupported) can and cannot prove, and a
  model-level validator rejects indirect evaluations from being
  high-confidence-`ok`.
- When a Microsoft API cannot support the claim, the product changes the claim
  rather than forcing the data (see the entitlement/denominator rules).

### 3. Where did this license mapping come from?

- Every `servicePlanId` GUID is asserted against the Microsoft licensing
  reference; the audit (`audit/entitlement-audit.md`) records source, date, and
  the corrections applied (including the `THREAT_INTELLIGENCE` plan-label fix
  and the `MDE_LITE` GUID addition).
- Mappings carry `source_version`, `docs_url`, and the offline validator
  `scripts/validate_sku_catalog.py` enforces GUID↔name consistency fail-closed.

### 4. How does this handle pagination?

- Collectors page their reads and record `truncated` markers when a sample hits
  the page cap (MDE machines, Intune managed devices, sign-in lookbacks).
- The quality policy downgrades confidence and caps any would-be `ok` to
  `partial` when a sample is truncated, and adds a limitation naming the
  truncation. A truncated sample is never presented as the population.

### 5. What happens if permissions are missing?

- A missing permission yields an explicit `error`/`partial` finding with a
  limitation naming the permission and a portal pointer. It is never a silent
  empty success and never counted as a security gap.
- `doctor` surfaces permission prerequisites; `docs/permissions.md` lists the
  full permission-to-check mapping.

### 6. Why is this denominator valid?

- License seats are **never** a device/population denominator. A coverage
  percentage is computed only against an authoritative eligible-device inventory
  (`eligible_devices`); absent that, the product reports *observed enrollment*
  as a licensing-leverage signal capped at `partial`, never "coverage" and never
  `ok`. See `eval def.*mde_onboard_gap.py` / `endpoint_intune_enrollment.py` and
  `docs/methodology/entitlement-model.md`.

### 7. What does this score actually mean?

- `% realized = fully_working / you_own` over owned capabilities with in-scope
  evaluated checks, scoped to the priority packs scanned. It is **not**
  "you are X% secure." It exposes the denominator and all sides
  (`you_own`, `fully_working`, `needs_attention`, `partly_set_up`,
  `not_licensed`) and never penalizes unowned or unevaluated surfaces.
  See `docs/methodology/scoring.md`.

### 8. How does this differ from Maester?

- Maester = continuous Pester config tests; Secure Score = numeric posture
  scoring (not SKU-gated); CIPP = MSP tenant administration; Lighthouse =
  partner multi-tenant management. LicenseLens = **entitlement-aware security
  activation assessment** (owned SKUs → expected high-value controls → observed
  usage → activation gap), complementary, not a replacement. See
  `docs/comparison.md` and `docs/methodology/assessment-model.md`.

### 9. Why should an MSP care?

- The MSP workflow (portfolio → assess entitlements → activation gaps →
  prioritize → backlog → deliver → reassess → QBR) is documented in the
  product-methodology and `docs/msp-batch.md`. `licenselens batch tenants.yaml`
  runs many tenants with per-tenant isolation and an index. Activation backlog
  and reassessment/diff turn findings into a billable work queue.

### 10. How do I know this report isn't AI-generated guesswork?

- Scoring, PASS/GAP status, entitlement, coverage, and licensing are all
  **deterministic**: identical normalized evidence always yields the same
  finding. The report exposes each finding's evidence, data source, evaluator
  observation, confidence, and reference. LLM judgment is explicitly
  non-authoritative (see `docs/methodology/` and the AI-positioning statement).

### 11. Where are the limitations?

- `docs/limitations.md` (operational) and `docs/methodology/limitations.md`
  (principle). Every affected finding carries its own limitation inline. Known
  structural limits (email pack off by default, proxy/manual surfaces, Sentinel
  workspace requirement, truncation, advisory-not-certification) are stated
  plainly.

### 12. Can I reproduce the result?

- Deterministic demo fixtures + a recorded golden-tenant replay
  (`tests/fixtures/golden-tenant.json`, `tests/test_golden_tenant.py`) reproduce
  a scan outcome exactly. Deterministic generated artifacts (reference docs,
  sample report) are byte-identical across runs (enforced by the release gate).

### 13. Can I inspect the raw evidence?

- Yes. Findings carry normalized `evidence` (raw counts/object samples) and
  `data_sources`. The report's evidence view exposes what was queried and found.
  `docs/methodology/evidence-model.md` documents the traceable evidence path.

### 14. What happens when Microsoft changes an API?

- The release gate runs codespell/lychee/MkDocs-strict and regenerates
  reference docs deterministically; API/endpoint changes are recorded in
  `CHANGELOG.md` and `docs/limitations.md`. The entitlement catalog is pinned
  to the Microsoft licensing table's date and must be re-validated before each
  conference release. The offline SKU validator fails closed if a mapping drifts.

### 15. Can I dispute a check?

- Yes. Six issue templates (`.github/ISSUE_TEMPLATE/`) and
  `docs/practitioner-validation.md` define how to challenge false positives,
  false negatives, API inconsistencies, licensing, methodology, and edge cases —
  each with sanitized-evidence and primary-source requirements.

### 16. Can I run this safely across hundreds of tenants?

- Read-only against tenants (no write Graph/Azure APIs). Batch runs
  per-tenant with isolation and an index; a failing tenant does not abort the
  batch. Reports are redacted by default, secrets go through env vars/secret
  managers, and no telemetry is sent. See `SECURITY.md`, `docs/msp-batch.md`,
  and `docs/app-registration.md`.

## Residual limitations (honestly stated)

- **No recorded real-tenant falsification yet** — the validation framework and
  dashboard report this as zero until a controlled tenant run is recorded and
  fingerprints are falsified.
- **Some surfaces are proxy/manual** by necessity (email config has no Graph read
  API; Purview/MDI surfaces are labeled proxy) and are disclosed per check.
- **Large-tenant sampling** may truncate; samples are labeled.
- **Not a compliance certification** and not a substitute for Microsoft Secure
  Score, Maester, CIPP, or Lighthouse.

A skeptical reviewer who reads the codebase, the methodology, and the
validation framework will find: the product states what it measured, documents
what it cannot prove, and fails closed when evidence is missing. That is the
vibe-code-resistance standard the product holds itself to.

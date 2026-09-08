# Practitioner validation

Security License Lens is meant to survive technical scrutiny from Microsoft
security practitioners and MSP operators. This page explains **what needs
validation, how to challenge a check, and how to add tenant-safe evidence** so
reviewer disagreement becomes useful product input.

## Why external validation matters

A check's unit tests passing is **necessary but not sufficient** for it to be
considered valid. Test fixtures are synthetic or recorded from controlled runs;
a real tenant can always surprise. The product tracks a per-flagship
practitioner-validation status so a skeptical reviewer can see exactly which
checks have been examined by an independent human and which still need it.

The maturity dashboard headlines the share of flagship assessments meeting the
full trust standard — not the number of checks — precisely because external
validation, not volume, is the signal of maturity.

## What needs validation

- **Flagship checks** (see `catalog/flagships.yaml`) are the priority: the
  checks that may be demonstrated publicly. Each must have a defensible security
  intent, a correct entitlement mapping, a real evidence path, a deterministic
  evaluator, and honest terminology.
- **Licensing mappings** (`catalog/capabilities.yaml`, `catalog/sku_service_plans.yaml`)
  — every `servicePlanId` GUID is asserted against the Microsoft licensing
  reference and can be disputed with a primary source.
- **Denominator decisions** — any check that reports a coverage/utilization
  percentage must use an authoritative population, not license seats as a proxy
  for device count (see the entitlement-model methodology).
- **Uncertainty handling** — whether the right status/confidence was chosen when
  evidence was missing, partial, or permission-blocked.

## How to challenge a check

Open an issue using the matching template. The six validation templates cover:

| Issue template | Use when |
|---|---|
| False positive | A check reported a gap that is not a real gap |
| False negative | A real gap exists that LicenseLens did not flag |
| Microsoft API inconsistency | The API result conflicts with the portal/other data |
| Licensing correction | A SKU/plan/entitlement mapping is wrong or missing |
| Evaluator methodology challenge | The evaluator logic or claim overstates the evidence |
| New edge case | A configuration the check does not handle |

Each template asks for the `check_id`, what the report said, the sanitized
evidence, why you believe the current behavior is wrong, and references.

## What an issue should include

- The **`check_id`** and the exact finding status/summary from the report.
- **Sanitized evidence**: redacted report JSON/HTML, admin-console screenshots,
  or a minimal tenant-safe JSON fixture. **Never** include customer tenant IDs,
- user principal names, client secrets, tokens, or unredacted live reports.
- Your interpretation and the **primary Microsoft source** that supports it
  (Microsoft Learn, licensing reference, product docs, SCuBA, or a recognized
  standard). Blog posts and community assumptions are not accepted as authority.
- Environment: package version, auth mode, approximate tenant size, and cloud.

## How to submit edge cases

Prefer a minimal, **tenant-safe fixture**. A fixture reproduces the edge case
without any real identifiers. Good fixtures are small, deterministic, and show
exactly which evidence the check mis-handles. See the check-development docs for
the fixture shape used by the test suite.

## How to propose changed semantics

Use the **Evaluator methodology challenge** template. Explain which concept is
conflated (for example: configuration vs. effectiveness, license seats vs.
device population, absence of evidence vs. evidence of absence) and what the
correct status/confidence/wording should be. Methodology changes are reviewed
against the public methodology (`docs/methodology/`) before code changes.

## How to dispute a licensing mapping

Use the **Licensing correction** template and provide a primary Microsoft
source. Because the catalog is GUID-backed and validated offline
(`scripts/validate_sku_catalog.py`), a correct correction that carries the
authoritative GUID/plan name can be applied deterministically and locked with a
test.

## How additions land

1. Open an issue with the template (or comment on an existing one).
2. Maintainers/contributors reproduce the finding against the evidence.
3. The correction is applied with a test that prevents regression.
4. The check's practitioner-validation status and the maturity dashboard are
   updated to reflect the review.

## Sensitivity rules

- Reports are redacted by default; still treat JSON/ZIP artifacts as sensitive.
- Never commit customer tokens, `.env` files, live reports, or unredacted
  exports.
- Real-tenant validation results are recorded only in sanitized form. Integer
  counts default to zero; the rejection share is unmeasured until a confirmed
  or rejected observation exists. See [validation recording](validation-recording.md).

## Pilot packet (2026-09-07)

This is a recruitment and measurement packet, not a completed pilot. Do not
send invitations without the owner's authorization. Do not treat agent
reenactment as a completed human gate.

### Selected flagship set (8)

Repaired endpoint, entitlement, and Conditional Access claims, plus already-working
scoped-CA cases:

1. `endpoint-enrollment-coverage` — Entra ∩ Intune matched population
2. `mde-onboard-gap` — Intune ∩ MDE matched population
3. `id-ca-mfa-all-users` — scoped-CA regression (already passing negative/control)
4. `id-ca-legacy-auth-block` — Security Defaults / legacy-auth interaction
5. `id-ca-priv-gaps` — privileged MFA + legacy
6. `id-protective-plan-assignment` — mixed assignment, not "E5 so every user"
7. `sen-telemetry-ingestion-coverage` — unknown vs measured-absent ingestion
8. `sen-rule-telemetry-parity` — live-rule count only from qualifying evidence

All remain `draft` until a human practitioner marks them.

### Case matrix

Distinguish synthetic/lab from permissioned real environments. Not every cell
needs its own tenant.

| Case | Purpose |
|---|---|
| Business Premium | entitlement floor; CA available, many Defender add-ons not |
| E3 + add-ons | mixed ownership without a single SKU story |
| E5 with mixed assignment | owned SKU ≠ every user holds the plan |
| Missing Graph/ARM permissions | unknown/error, never not-licensed or OK |
| Partial collection / truncated inventory | unresolved, never 100% |
| Overlapping device inventories | legitimate positive control |
| Entirely disjoint device inventories | matched coverage 0 of N, never OK |

### Reviewer criteria

Challenge the claim, do not approve a checklist. Produce a counterexample or a
legitimate positive control. Derive expected status from the claim, the case,
and a primary Microsoft source — not from the tool's current wording.

### Recruitment draft (do not send without authorization)

Subject: Request for a 45-minute LicenseLens paired assessment

I am looking for Microsoft security consultants/architects (or MSP security
leads) willing to spend about 45 minutes on a paired assessment of a
permissioned lab or customer tenant you already operate.

Procedure: you assess the tenant with the tools you normally use and write down
your top three decisions. I then show LicenseLens on the same scope. We record
what changed, why, and whether the incremental decision was meaningful, faster,
disputed, or harmful.

No production consent on my hardware. Outputs stay with you unless you
explicitly approve a sanitized excerpt. Flagships remain draft; this is
falsification, not a product endorsement.

### Paired-assessment protocol

1. Record the operator's top three decisions using their normal tools
   (Secure Score / CIPP / Maester / portals / spreadsheet) *before* revealing
   LicenseLens.
2. Run LicenseLens on a comparable, consented scope.
3. Record: useful / unchanged / disputed / harmful recommendations; time to a
   usable work package; permission friction; time spent investigating a false
   finding; support needed.
4. At the next genuine assessment / change / QBR occasion, record whether they
   reuse it without the maintainer operating it. No compulsory weekly usage.

Target samples (pilot gates, not population inference): four independent
specialists for paired decisions; two independent reviewers seeking flagship
counterexamples; three intended operators for unassisted installation; three
technical leads and three business decision-makers for first-screen
comprehension (what does the number measure, what is unknown, what would you
authorize next — do not explain first). Report actual unique participants.

### Evidence record fields

run/build identity · case/scope · observed conclusion · reviewer adjudication ·
rationale · corrective action · permitted publication status. Sensitive
artifacts only in approved locations. Public fixtures synthetic or specifically
approved.

### Calendar review

Proposed review date: **2026-10-20** (six weeks from this session, allowing
recruitment). If recruitment stalls, that is distribution evidence — not a
reason to start WS7 or add workloads.

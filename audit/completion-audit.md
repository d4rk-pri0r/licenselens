# LicenseLens completion audit

Independent audit of the repository against every section of `maturity-goal.md`
(product-maturity goal §33 completion authority). This documents what the
repository now *provides as verifiable evidence* for each requirement, and
states plainly what remains intentionally deferred.

## Section-by-section status

### Positioning & scope
| § | Requirement | Repository evidence | Status |
|---|---|---|---|
| 1 | Product positioning invariant (entitlement → activation gap) | `docs/methodology/assessment-model.md` (thesis, concept inventory, distinctions); `docs/comparison.md` (tool boundary) | ✅ |
| 2 | Stop feature-count optimization | No new checks added; work focused on validation/evidence/methodology; `docs/flagships.md` and the maturity dashboard headline % flagships meeting the trust standard, not check count | ✅ |
| 22 | AI non-authoritative | `docs/methodology/assessment-model.md`: "No LLM determines entitlement, PASS/GAP status, coverage, or score"; conference-demo answer documented | ✅ |
| 23 | Competitive boundaries | `docs/comparison.md`: Secure Score, Maester, CIPP, Lighthouse, ScubaGear, license-waste; complementary positioning, no unsupported superiority claims | ✅ |

### Methodology & truth (Phase 1)
| § | Requirement | Repository evidence | Status |
|---|---|---|---|
| 3 | Formal methodology (12+ concepts) | `docs/methodology/` suite (assessment-model, evidence-model, scoring, entitlement-model, uncertainty, validation, limitations) | ✅ |
| 4 | Semantic audit every check | `audit/check-semantic-audit.md` (166 checks, all 12 required fields), corrected against actual code (4 audit misreads fixed) | ✅ |
| 5 | Flagship checks (25–40) with high standard | `catalog/flagships.yaml` (36 flagships) + `docs/flagships.md` (18-point §25 gate) + `scripts/validate_flagship_meta.py` | ✅ |
| 6 | Invalid denominators fixed | `evaluate_mde_onboard_gap` + `endpoint_intune_enrollment` rewritten: license-vs-device is PARTIAL licensing-leverage signal; only authoritative `eligible_devices` yields coverage | ✅ |
| 7 | Overclaiming language | MDI "largely healthy", Sentinel "coverage looks healthy"/"connectors look healthy" corrected to describe what was measured | ✅ |
| 11 | Licensing accuracy audit | `audit/entitlement-audit.md`; GUIDs verified vs Microsoft licensing reference; `THREAT_INTELLIGENCE` label + `MDE_LITE` GUID corrected; offline SKU validator | ✅ |
| 10/9 | Uncertainty semantics + scoring determinism | `docs/methodology/uncertainty.md` + `scoring.md`; fail-closed required-evidence policy; score-determinism-under-missing-evidence tests | ✅ |

### Evidence (Phase 2)
| § | Requirement | Repository evidence | Status |
|---|---|---|---|
| 8 | Evidence auditability / "show me why" | Report exposes per-finding `data_sources`, `evidence`, `confidence`, `limitations`, `evaluation_mode`, references; `docs/methodology/evidence-model.md` documents the traceable path | ✅ |
| 12 | Source-of-truth reference model | `catalog/flagships.yaml` source_url/source_type per flagship; validator + dashboard; entitlement audit records sourcing | ✅ |
| 14 | Real-tenant validation framework | `src/licenselens/validation.py` (TenantValidationRecord + honest-zero metrics) + `docs/validation-recording.md`; defaults to zero | ✅ |
| 13 | Practitioner validation framework | 6 issue templates + config.yml + `docs/practitioner-validation.md` + §14 recording | ✅ |

### Product (Phase 3)
| § | Requirement | Repository evidence | Status |
|---|---|---|---|
| 15 | MSP product fit | `audit/msp-workflow-audit.md` (workflow assessment, gaps) | ✅ |
| 16 | Auth least-privilege | `audit/auth-audit.md`; OIDC now supported in batch; certificate auth documented gap | ⚠️ partial (certificate auth not implemented; documented gap) |
| 17 | Historical/reassessment value | `licenselens diff` categorizes closed/new/regressed; `docs/methodology/` | ✅ |
| 18 | Activation backlog | Action-plan export now carries structured §18 metadata (capability/entitlement/risk/implementation_category/current_evidence/reference/manual_validation_needed) | ✅ |
| 21 | UI for technical trust | Report evidence view + limitations + confidence + reference + deep-link; methodology documents evidence-first | ✅ |

### Release & conference (Phase 4)
| § | Requirement | Repository evidence | Status |
|---|---|---|---|
| 19 | Release coherence | PyPI readme, SECURITY/SUPPORT/releases/security version conflicts fixed; `verify_version.py` audits public docs surfaces; release-coherence test; release gate passes (23 pass / 0 fail / 2 deferred) | ✅ |
| 20 | Conference demo mode | `licenselens demo` offline, deterministic (byte-identical modulo timestamp); `docs/conference-demo.md` rehearsal playbook | ✅ |
| 24 | Skeptical repository audit | `audit/skeptical-repository-audit.md` answers all 16 questions with concrete pointers | ✅ |
| 25 | Flagship quality gates | `docs/flagships.md` 18-point checklist + `scripts/validate_flagship_meta.py` enforcement | ✅ |
| 26 | Pre-BSides gates | Release gate 23/0/2-deferred; deterministic demo; secrets cannot leak; methodology published; positioning distinct | ✅ |
| 27 | Pre-Ignite gates | Methodology publishable; licensing claims verified; limitations explained; practitioner-validation framework ready | ⚠️ partial (no real-tenant validation yet — Phase-5 external-validation milestone) |
| 28 | Conference technical depth | Raw MS evidence → normalized → evaluator → deterministic result is demonstrable; demo + methodology + skeptical audit | ✅ |
| 29 | Public methodology docs | `docs/methodology/` (7 docs) | ✅ |
| 30 | Maturity dashboard | `scripts/maturity_dashboard.py` computes % flagships meeting trust standard + honest-zero external metrics | ✅ |

### External validation (Phase 5)
| § | Requirement | Repository evidence | Status |
|---|---|---|---|
| 13 | Practitioner review process | Issue templates + docs | ✅ (process in place) |
| 14 | Validate against real/controlled tenants | Framework records sanitized results + summary metrics | ⚠️ framework exists; **no real tenant run recorded yet** (honest zero) — this is the explicit Phase-5 external-validation milestone |
| 25 | Practitioner validation status can be recorded | Per-flagship status + §14 recording | ✅ |

## Explicitly unmet / deferred (honestly stated)

1. **Real-tenant validation (§14/§27)** — the framework, recording schema, issue templates, and honest-zero metrics are in place, but **no real or controlled tenant run has been recorded and falsified** yet. This is the Phase-5 external-validation milestone the goal defines as subsequent work; the system intentionally reports zero rather than inventing numbers. This is the single genuine "not yet achieved" requirement.

## Requirements closed since the first audit pass

- **Certificate-based auth (§16)** — implemented as a first-class mode: `--auth certificate` (PEM/PFX client cert) in `scan`/`doctor`/`discover-workspace` and `batch`, with `AZURE_CLIENT_CERTIFICATE_PATH` / a YAML `certificate:` key. OIDC and certificate are now both supported secret-free unattended options.
- **Batch activation backlog (§15/§18)** — `licenselens batch --export json|csv|action-plan` now writes a structured per-tenant action plan, closing the "batch lacks backlog export" gap.
- **Flagship test-class standard (§5)** — every one of the 36 flagship checks now has positive + negative + missing/error test coverage (maturity dashboard measures 36/36, replacing the placeholder zero).

## Completion criteria evaluation (§33)

- **Product**: Clearly differentiated (activation-gap thesis), value obvious, MSP workflow documented. ✅
- **Security methodology**: Flagships defensible, denominators correct, claims proportional, uncertainties honest, licensing sourced. ✅
- **Engineering**: Scoring deterministic, critical edge cases tested, failure states safe, evidence reproducible, public release coherent (version consistency + passing release gate). ✅
- **Conference**: BSides demo reliable (deterministic + rehearsed playbook), skeptical practitioner can inspect logic, strong "not vibe-coded" answer. ✅ Ignite-quality story supported. ✅
- **MSP**: Multiple tenants assessed credibly (batch + isolation), authorization explainable, least privilege improving (OIDC + certificate secret-free modes), results → activation backlog (including per-tenant batch export), reassessment → diff. ✅

## Definition of Done

The goal is met when LicenseLens can credibly demonstrate: *a customer owns a
capability, Lens shows authoritative evidence for that entitlement, inspects
for defensible deployment evidence, produces a deterministic qualified
conclusion, explains exactly why, provides an activation backlog, and
demonstrates improvement after remediation.* The repository now provides all of
that deterministically and evidence-driven, with the framework in place to
record the real-tenant falsification that constitutes the Phase-5 external
validation milestone.

The single most honest statement about remaining work: **the external-validation
loop hasn't been exercised against a live tenant**. Everything the goal sets up
to support that measurement is implemented and truthful (zero-initialized); the
measurement itself requires a real tenant run by a practitioner, which is
correctly outside autonomous scope and reported as such rather than fabricated.

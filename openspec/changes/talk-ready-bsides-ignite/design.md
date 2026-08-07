## Context

See `proposal.md` for motivation and calendar (talk-ready **Nov 10 2026**; B-Sides DE Nov 13–14; Ignite Nov 17–20).

Current codebase (v0.2 / 0.2.1-unreleased) already has: entitlement catalog, YAML checks, Graph/ARM/MDE collectors, identity evaluators, Secure Score proxies for MDO/MDI/Purview, strict proxy quality policy, HTML/MD/JSON reports with customer_* copy, `doctor`, `batch`, `diff`, workspace discover, exit codes. Gaps versus the sealed product spine: no capability rollup top card, no structured ranked moves with effort, no EXPOSED axis, MDO still proxy, first-run UX is clone-and-pip-e, estate index is thin, distribution not PyPI-first.

Constraints: Python 3.12+, Typer/Rich/httpx/pydantic/jinja2, read-only Microsoft APIs, MIT, no telemetry default, keep JSON artifact reasonably stable for MSP glue.

## Goals / Non-Goals

**Goals:**

- Extend the scan result + report pipeline to satisfy top-card, ranking, and exposure specs without rewriting the engine
- Make MDO email evidence honest and off the default talk path (spike Sep 21: no Graph API for MDO policy config); Secure Score proxy demoted to opt-in only
- Ship Monday path verbs and distribution suitable for non-dev operators
- Enrich batch index for MSP Friday triage
- Phase work so Truth (Sep) precedes Wow (early Oct) precedes Freeze (mid-Oct)

**Non-Goals:**

- SaaS, write/remediation APIs, dollarization, AI-generated findings
- Huntress branding in-product; competitor comparison findings
- Full Purview/Sentinel depth for talk plot (starter only)
- PSA/ticketing plugins (JSON stability only)
- Perfect Windows native installers pre-talk (Docker is the escape hatch)

## Decisions

### D1 — Extend ScanResult rather than parallel report model

**Choice:** Add fields on existing `ScanResult` / `Finding` / `CheckDefinition` (capability summaries rollup, `moves[]`, pack scope, exposure on findings) and teach HTML template to render the iconic card from those fields.

**Alternatives:** Separate “executive DTO” built only in the template layer — rejected because JSON/MSP index would drift from HTML.

**Rationale:** One contract feeds card, JSON, markdown, estate index.

### D2 — Check YAML grows metadata; loader validates

**Choice:** Add to each check YAML: `impact`, `effort`, `blast_radius`, `pack`, `exposure_class`, optional `deep_link`. Map existing `severity`/`value_impact` into `impact` during migration then prefer new fields. Fail load or CI if enabled checks miss required keys.

**Alternatives:** Hardcode ranking in Python per check id — rejected (not contributor-friendly, hides SME judgment).

### D3 — Ranking function (deterministic, published)

**Choice:** Score ≈ `impact_weight × exposure_boost × confidence_weight / effort_penalty`, with pack tie-break (identity > email > endpoint > starter) and stable `check_id` final tie-break. Document weights in code comments + docs/limitations or architecture.

**Alternatives:** Manual ordered list only — too rigid; ML — out of freeze.

### D4 — EXPOSED via finding flag + optional CA evaluator split

**Choice:** Add `exposure_class` on `Finding`. Implement legacy-open and MFA-less-GA logic in CA-related evaluators (extend `id-ca-priv-gaps` and/or emit companion finding ids). Card counts findings where `exposure_class == exposed`.

**Alternatives:** Separate CSPM engine — rejected (dilutes thesis). Only chip without structured field — rejected (index/JSON need it).

**Break-glass:** Document exclusion pattern (named emergency accounts / group) so clean break-glass does not false-EXPOSE; prefer under-fire to over-fire on GA MFA if uncertain.

### D5 — MDO email pack (spike-driven)

**Choice:** Spike (Sep 21) found no Graph v1.0/beta API reads MDO email security policy config (preset Standard/Strict, Safe Links, Safe Attachments). Microsoft exposes this state only via Exchange Online PowerShell cmdlets (`Get-ATPProtectionPolicyRule`, `Get-SafeLinksPolicy`, `Get-SafeAttachmentPolicy`), which need an interactive session — not our app-only Graph auth. `exchangeProtectionPolicy` in Graph is M365 Backup/retention, unrelated.

Decision: email pack drops from the default talk demo; identity + endpoint carry the stage. `mdo-p2-policies-default` keeps its id for diff continuity but is excluded from default pack scope. Evidence only via explicit operator opt-in:
- labeled degraded Secure Score proxy (strict proxy quality policy; never rolls up to fully working), or
- research-only Exchange Online PowerShell collector (interactive, opt-in) reading preset/Safe* policy state.

**Alternatives:** Stay on Secure Score until after talk — rejected by product decision. Full EXO PowerShell as the primary path — worse operator UX than Graph app-only; not viable for a conference demo.

**Contingency (realized):** Email drops from default demo; identity+endpoint still ship. Spec allows explicit degraded proxy only when operator opts in.

### D6 — Monday path commands

**Choice:**

- `licenselens demo` → dry-run scan + print HTML path (optional open)
- `licenselens quickstart` → read-only blurb → device code → org confirm → offer doctor/scan
- Improve `doctor` messages; introduce ready-enough exit semantics
- `scan` interactive completion prints CTA

Keep `batch` / `diff` / `discover-workspace` as MSP chapter, not new concepts on stage.

**Alternatives:** Single interactive TUI — higher cost; skip quickstart and docs-only — fails Persona A.

### D7 — Capability rollup rules

**Choice:** For each owned capability in scope of selected packs:  
`gap` if any related check gap; else `partial` if any partial/error/skipped/proxy-cap; else `ok` if all ok; exclude `not_licensed` from YOU OWN.  
`% realized = fully_working / you_own` (0 if you_own=0).

Related checks = checks whose `required_capabilities` contain that capability id (and check pack in scope).

### D8 — Distribution

**Choice:** Hatchling package already structured; publish to PyPI; document pipx; GHCR (or GHCR-compatible) image wrapping CLI; GitHub Release at freeze. CI publish can be manual trusted release for v1 to reduce supply-chain rush risk.

**Alternatives:** pip-only from git — fails conference one-command bar.

### D9 — Brand in artifacts not engines

**Choice:** Copy/strings/README/template seal only. No runtime branch on employer. Disclaimer blocks stay centralized in template + README.

### D10 — Phased delivery maps to tasks

| Phase | Gate date | Design focus |
|-------|-----------|--------------|
| P0 Foundation | Sep 1 | Models/metadata contract, lab seed plan, README hero draft, brand heads-up |
| P1 Truth | Oct 1 | Exposure rules, identity harden, MDO direct, rollup, starter demotion |
| P2 Wow | Oct 15 | demo/quickstart/doctor, card HTML, estate index, pipx/Docker, MSP docs |
| P3 Freeze | Nov 1 | sample=slides, limitations, recorded demo, rc tag |
| P4 Ship | Nov 10 | release, deck, CTA live |

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| MDO email policy config not readable via Graph (PowerShell-only) | Spike Sep 21 confirmed; email dropped from live demo; opt-in proxy/EXO paths only |
| Device code blocked by CA | quickstart English rail → app-only docs; rehearse Path B |
| EXPOSED false positives on stage | Under-fire bias; lab seeds; friend-tenant FP pass; break-glass doc |
| Scope creep (Sentinel deep, more EXPOSED) | Freeze sticky Oct 15; starter label |
| Windows install friction | Docker alternate tested on clean Win VM |
| JSON field additions break unknown consumers | Additive fields only; keep legacy `recommended_next_steps` populated from moves |
| CFP rejection | Product date still Nov 10; Ignite hallway + public drop |
| Huntress brand concern | Manager one-pager in P0 before amplification |

## Migration Plan

1. Additive model fields → template feature-detect with sensible fallbacks until card complete  
2. Check YAML metadata backfill in one PR; pin tests on loader validation  
3. Email pack off default talk path; Secure Score proxy / EXO collector opt-in only; update dry-run fixtures/sample report  
4. Publish PyPI when Wow exit nears (can publish 0.3.x prereleases)  
5. Freeze: no check id renames after Oct 15 without diff notes  
6. Rollback: any bad PyPI yank + pin previous tag; engine remains runnable from git

## Open Questions

- (resolved by spike) MDO email policy config is Exchange Online PowerShell-only; no Graph read path — `mdo-direct` spec and D5 updated accordingly
- Whether `id-ca-priv-gaps` splits into multiple check ids or multi-signal one check with multiple moves (implementation detail; card cares about findings/moves)
- Final version number label: `v0.9.0` vs `v1.0.0` for talk-ready (marketing honesty; pick at freeze)

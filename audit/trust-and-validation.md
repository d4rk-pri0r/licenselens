# Trust-and-validation execution record

Durable ledger for the repair program that answers the 2026-09-07 senior-panel
evaluation ("fix false certainty from raw input through the final sentence, and
prove one independent assessment-to-decision-to-reassessment loop before adding
product breadth"). This file is the single source of truth for what is done,
what is verified, and what is still open. Update it after every accepted task or
material blocker.

Two outcomes are tracked separately and never merged into one percent:

- **Engineering readiness** — code, tests, docs, candidate build. Agents and
  tests can close these.
- **External validation** — independent practitioners, permissioned tenants,
  a completed work package. Only humans can close these.

Passing tests and agent review are engineering evidence. They are not
practitioner validation and never justify marking a flagship `validated`.

## Baseline (established 2026-09-07, session start)

| Item | Observed |
|---|---|
| Repository | `d4rk-pri0r/licenselens`, branch `main` |
| Commit at start | `5cfb1ef` = `origin/main`, clean tree (same commit the evaluation reviewed) |
| Package version | `0.4.0` in `pyproject.toml`; PyPI serves `0.4.0` (older semantics; no `[mcp]` extra, no `plan`, no `--tier`) |
| Test count at start | 1,581 non-browser + 105 browser (per evaluation); re-verified after WP1 |
| Orchestration | Hermes session on `claude-fable-5-1` (Anthropic) as accountable lead; OpenCode `Sisyphus` on `zai-coding-plan/glm-5.3` / `glm-5.3-flash` for bounded implementation; DeepSeek `deepseek-v4-flash` is the quota/hang fallback. `opencode auth list` shows Z.AI Coding Plan + DeepSeek credentials present |
| Roadmap change | WS7-A..E (MCP granular tools, attestation, history, waivers, hunting KQL, ADO/Jira exports) **deferred**; no longer the default next phase. Recorded in `.omo/plans/master-sequence-differentiation.md` |

### Finding-by-finding reproduction (attached `domain-probe.py`, re-executed on `5cfb1ef`)

| Evaluation finding | Status at baseline | Evidence |
|---|---|---|
| F2-P0 disjoint device populations → OK/100% (both endpoint evaluators) | **reproduced** | probe: `mde_coverage_of_intune=0.0`, `mde_verdict=ok`, "10 of 10 eligible … (100%)"; same for Intune. Root cause: `defender_endpoint.py:43-45` and `endpoint_intune_enrollment.py:47-49` take the reconciliation *denominator* (`intune_active` / `entra_active`) but keep the *unmatched* numerator (`onboarded_machines` / `len(managed_devices)`), so the matched ratios the helper already computes (`mde_coverage_of_intune`, `intune_coverage_of_entra`) are ignored |
| F2-P0 unknown entitlement → summary `not_licensed: 4` | **reproduced** | probe `unknown_rollup`: findings `{error: 10}`, rollup `not_licensed: 4`. Root cause: `engine/rollup.py:79-85` computes `not_licensed = referenced - owned` without an unknown set |
| F2-P0 detection view: missing ingestion → `ingesting=False`; positive ingestion + parity **error** → `watched_by=1` | **reproduced** | probe `detection_no_evidence` / `detection_parity_error`. Root cause: `report/viewmodel.py:788-796` uses a Boolean `ingesting` with no "unknown", and infers `watched=1` whenever a parity finding exists and the table is not in `unwatched_tables`, regardless of parity finding status |
| F2-P1 validation metrics: 2 rejected / 0 confirmed → FP rate `0.0`; 2 rejected / 1 confirmed → `2.0`; repeated runs summed vs confirmations deduped | **reproduced** | probe `all_rejected`, `more_rejected`, `repeated_runs`. Root cause: `validation.py:54-64` |
| F3 wizard renders escaped HTML (0 forms, 0 buttons) | **reproduced by source inspection** | `ui/pages.py:141-143` renders `mode.html` to `str`, then passes it into autoescaped `shell.html` `{{ body }}`. Browser click test pending (WP3) |
| F3 hotel-room promises timestamped outputs; report guide documents flat output | **reproduced by source inspection** | `docs/hotel-room.md:38` vs `docs/report.md:8-12`; literal-command verification pending (WP3) |
| F4 8 owned / 25 licensed / 11 in distribution; "fully working"; duplicated explanation | **reproduced** | attached screenshots `tree-1280`, `public-1280`; `templates/report.html.j2:303-325` appends `not_licensed` to the owned-capability bar |
| H4 after-overlay removes Security Defaults without legacy-auth block → new gap + EXPOSED, headline 38% unchanged | **reproduced** | attached `demo-diff.json`: `new_gaps: [id-ca-legacy-auth-block]`; `collectors/runtime_envelopes.py:223-263` |
| All 36 flagships `draft` | **confirmed, intentional** | probe `flagship_status`; stays `draft` until a human practitioner validates |
| CA scoped-policy regression probe passes | **confirmed positive control** | evaluation; not re-run here (no change to CA code planned) |

## Task ledger

Statuses: `ready`, `in progress`, `needs review`, `verified`, `blocked`,
`awaiting external evidence`, `deferred`.

| ID | Pri | Work package | Depends on | Owner | Status | Acceptance gate | Evidence / blocker |
|---|---|---|---|---|---|---|---|
| WP0 | 0 | Baseline, freeze, ledger, reviewer packet skeleton | — | Fable | **verified** | this file exists; probe re-run; WS7 deferred in master sequence | this section |
| WP1 | 1 | Endpoint matched-population contract (`device_reconcile` → both evaluators → HTML/JSON/action-plan) | WP0 | Fable (contract) + GLM (impl) | **verified** (engineering) | disjoint → GAP 0/N through HTML/JSON/action-plan; 75 tests; probe DEFECT_CLOSED | `.omo/evidence/tv-1/ATLAS-VERDICT.md` |
| WP2 | 2 | Unknown entitlement in rollup; detection view unknown/watched semantics; error≠partial; headline fraction + denominator; distribution bar separation; "fully working" wording | WP1 (shared rollup/report contract) | Fable + GLM | ready | probes 1–4 in prompt §5 pass end-to-end; 8/25/11 mismatch gone; JSON/MD/CSV agree with HTML | — |
| WP3 | 3 | Wizard autoescape fix + hostile-text regression + real browser click; release truth (installed candidate, public 0.4.0 matrix, before/after retention docs, redaction doc reconciliation, classifier/maturity claims) | WP1–2 for acceptance | Fable + GLM | ready | Playwright clicks "Run the offline demo" and reaches a report; clean-venv wheel install runs demo/ui/mcp; docs matrix published | — |
| WP4 | 4 | Demo after-overlay coherent (legacy-auth block added or regression explicitly taught); baseline/after/diff runbook | WP1–3 | Fable + GLM | ready | every diff row accounted for; no manufactured aggregate | — |
| WP5 | 5 | Validation metric units (`validation.py`); pilot packet | WP0 | Fable in-process | **verified** (engineering); invitations **not sent** | 2r/0c → 100%; 2r/1c → ~66.7%; 0 adjudicated → unmeasured; duplicate `record_id` ignored; 14 tests; packet in practitioner-validation.md; review date 2026-10-20 | `src/licenselens/validation.py`, `docs/practitioner-validation.md` |
| WP6 | 6 | Three findings → one work package template; action-plan export corrections (`current_evidence`, first-entitlement, ordering) | WP2 | Fable + GLM (template/export) ; human (customer) | ready → **awaiting external evidence** for closure | template + export fixed; real closure needs an operator/customer | — |
| WP7 | 7 | Positioning copy corrections with dated primary sources; contribution/teaching/paid tracks separated; pilot review date | WP5 packet | Fable | ready | no unverified comparison claims remain; review date set | — |

## Human / external gates (cannot be closed by agents)

| Gate | Needs | Smallest next action for the owner |
|---|---|---|
| Pilot recruitment | 4 paired-decision specialists, 2 hostile flagship reviewers, 3 unassisted installers, 3+3 comprehension readers | Send the recruitment draft in `docs/practitioner-validation.md` (WP5 output) once the candidate build exists |
| One closed work package | willing operator/customer, authorized change, reassessment | Pick the customer; use the WP6 template |
| Flagship `validated` marking | human practitioner review per flagship | after hostile review |
| Release promotion (tag/publish 0.5.0) | fresh explicit authorization; `release_gate.py` green | not before WP1–5 verified |
| Lab scans (WS2-B, WS4-A, WS4-B manual-lab-pending) | Joe's lab tenant | unchanged from master sequence |

## Deferred (not the default next task; each needs a named active user before revival)

WS7-A MCP granular tools/attestation · WS7-B history store · WS7-C waivers ·
WS7-D hunting KQL · WS7-E ADO/Jira CSV · hosted scans · GDAP · paid tiers ·
new workloads · live-onboarding UI · report re-theming.

## Decisions

- D-T1 (2026-09-07): Execution record lives in `audit/` (tracked convention for
  audit/completion records), not `docs/` (public mkdocs tree, strict build).
- D-T2: WP1 contract — see below. Both endpoint claims use the **matched**
  numerator the helper already computes; the evaluators stop reading raw
  `onboarded_machines` / `len(managed_devices)` as the numerator whenever
  reconciliation is available.
- D-T3: Unknown entitlement is a first-class rollup population
  (`entitlement_unknown`), never folded into `not_licensed`.

## WP1 contract — endpoint population claims

Two different claims, two different relationships. Neither is "three-way
intersection".

| Claim | Check | Eligible denominator | Numerator | Matching key |
|---|---|---|---|---|
| Intune enrollment coverage | `endpoint-enrollment-coverage` | Entra devices with `accountEnabled != false` and `approximateLastSignInDateTime` within the window (`entra_active`) | members of that same set that appear in Intune `managedDevices` (`entra_active ∩ intune_managed`) | Entra `deviceId` ≡ Intune `azureADDeviceId`, lower-cased GUID |
| MDE protection coverage | `mde-onboard-gap` | Intune-managed devices with `lastSyncDateTime` within the window (`intune_active`) | members of that same set that appear in MDE with `onboardingStatus == "Onboarded"` and `lastSeen` within the window (`intune_active ∩ mde_active`) | Intune `azureADDeviceId` ≡ MDE `aadDeviceId`, lower-cased GUID |

Evidence states and what each permits:

| Evidence state | Conclusion allowed |
|---|---|
| All three inventories present, not truncated, eligible > 0 | ratio verdict: OK ≥ 0.85, PARTIAL ≥ 0.5, GAP < 0.5 (existing thresholds); disjoint → GAP "0 of N" |
| Any inventory truncated | ratio computed, capped at PARTIAL, confidence MEDIUM (existing) |
| Reconciliation collector errored / permission denied / `available: False` | fall back to the licensing-leverage proxy path: PARTIAL, `proxy: True`, never OK (existing) |
| Eligible population = 0 | PARTIAL "unresolved", never OK, no division (existing wording; must not become vacuous 100%) |
| Duplicate identifiers | set semantics; duplicates collapse to one device |
| Records missing the join identifier | excluded from both numerator and denominator; count surfaced in evidence as `unmatched_ids` when non-zero (new) |
| Stale / disabled | excluded by the window / `accountEnabled` filters (existing) |

Required acceptance cases (negative and positive controls): fully matched (OK),
partly overlapping (PARTIAL), entirely disjoint (GAP 0/N), duplicate rows (no
inflation), stale members (excluded), unmatched records (excluded, counted),
identifier-missing rows (excluded, counted), reconciliation unavailable
(proxy PARTIAL), empty eligible (unresolved PARTIAL). Trace at least the
disjoint and matched cases through `run_scan` → JSON → HTML wording →
action-plan CSV → diff.

## Session checkpoints

- 2026-09-07 — WP0 done; WP1 contract written; WP1 implementation dispatch next.
- 2026-09-07 — WP1 PASS (engineering). Disjoint inventories no longer produce OK/100%. Next: TV-2.
- 2026-09-07 — WP5 metrics PASS (engineering). Pilot packet written; do not send invitations.

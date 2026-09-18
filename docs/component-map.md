# Component map

This page is for someone joining the project, reviewing a proposed fork, or trying to answer “where does this conclusion come from?” It maps the product by responsibility rather than by directory listing.

## One scan, end to end

```text
CLI / UI entrypoint
  → auth context
  → collection plan
  → collectors
  → normalized evidence
  → evaluators
  → quality / uncertainty policy
  → rollup + ranking
  → report view model
  → HTML / JSON / Markdown
```

The system is local-first and read-only. A live scan uses the operator's credentials to read Microsoft APIs. A dry-run uses deterministic fixtures. The report is an artifact written to disk; there is no hosted control plane in this repository.

## Runtime layers

| Layer | Responsibility | Primary locations |
|---|---|---|
| CLI | Parses commands, flags, output paths, exit codes, and interactive prompts. | `src/licenselens/cli.py`, `src/licenselens/ui/` |
| Authentication | Builds device-code, client-secret, Azure CLI, OIDC, and dry-run contexts without embedding secrets in reports. | `src/licenselens/auth.py`, `src/licenselens/graph.py` |
| Planning | Resolves profiles, workloads, packs, tiers, backend preferences, and required evidence. | `src/licenselens/engine/planner.py`, `src/licenselens/engine/runtime_specs.py` |
| Collection | Performs read-only Graph, ARM, MDE, DNS, Secure Score, and PowerShell-bridge reads. | `src/licenselens/collectors/`, `src/licenselens/engine/runner_collect.py` |
| Evidence registry | Declares source keys, permissions, defaults, collector bindings, and runtime dependencies. | `src/licenselens/engine/_registry_source_meta.py`, `src/licenselens/engine/_registry_defaults.py`, `src/licenselens/collectors/bindings/` |
| Evaluation | Applies pure, deterministic check predicates to normalized evidence. | `src/licenselens/evaluators/`, `src/licenselens/engine/evaluate.py` |
| Quality policy | Demotes incomplete, proxy, manual, truncated, failed, or otherwise insufficient evidence so it cannot become false certainty. | `src/licenselens/engine/quality.py`, `src/licenselens/engine/limitations_policy.py`, `src/licenselens/models.py` |
| Rollup and ranking | Separates entitlement, assessment completeness, implementation state, headline percentage, and prioritized moves. | `src/licenselens/engine/rollup.py`, `src/licenselens/engine/rank.py` |
| View model | Converts `ScanResult` into stable presentation payloads: posture, capabilities, moves, findings, detection realization, provenance. | `src/licenselens/report/viewmodel.py` |
| Renderers | Produce offline HTML, bundle assets, JSON, Markdown, and optional ZIP output. | `src/licenselens/report/`, `templates/report.html.j2`, `templates/report_app/` |
| Catalog | Defines entitlements, capabilities, checks, profiles, telemetry expectations, and flagship metadata. | `catalog/`, `checks/` |

## Data contracts to preserve

### `ScanResult`

The portable result object is the boundary between scanning and reporting. It contains tenant-safe identity/provenance, owned capabilities, findings, capability outcomes, warnings, limitations, packs, moves, and rollup data.

If a new field is needed, prefer an additive schema change. Do not make the renderer infer security state from raw collector payloads.

### `Finding`

A finding is one check's conclusion. Important fields include:

- `check_id` — stable identity; never rename casually.
- `status` — `gap`, `partial`, `ok`, `not_licensed`, `error`, or `skipped`.
- `evaluation_mode` — direct, proxy, manual, or fallback mode.
- `confidence` and `limitations` — what the evidence permits.
- `evidence` and `data_sources` — inspectable support.
- customer-facing title, summary, remediation, next step, and admin link.

A finding is not proof of effectiveness. A direct configuration read can support a narrower claim than “the control is effective.”

### Capability outcome and rollup

Capability outcomes connect owned entitlements to a capability-level state. The rollup is intentionally not a raw finding count. It keeps:

```text
owned entitlement
  ≠ assessed population
  ≠ met criteria
  ≠ effective security
```

The headline percentage is generated from the rollup and its sentence, not hardcoded in a template.

## Report responsibilities

The report should remain a presentation of the result, not a second assessment engine.

- `src/licenselens/report/viewmodel.py` decides which customer-safe values are available.
- `templates/report.html.j2` is the single-file renderer.
- `templates/report_app/entry.html.j2` is the bundled renderer entrypoint.
- `templates/report/v2/` contains shared macros and partials for moves, capabilities, detection realization, finding belief blocks, and technical reference.
- `templates/report/v2/_v2_styles.css.j2` is the shared single-file foundation.
- `templates/report_app/v2/app.css` is the bundle stylesheet.
- `templates/report_app/v2/app.js` owns client-side filtering, sorting, pagination, exports, and capability/finding cross-filtering.

The narrative order is:

1. posture and implication;
2. prioritized decisions;
3. capability/entitlement context;
4. finding evidence;
5. technical reference and provenance.

If a new detail does not answer one of those reader questions, it belongs in technical disclosure or documentation, not in the main reading path.

## Adding a check safely

A new check crosses more seams than its YAML file suggests:

1. entitlement/capability mapping;
2. check definition and expected state;
3. collector/source metadata;
4. runtime dependency and binding;
5. evaluator implementation;
6. uncertainty/quality behavior;
7. reference and permission documentation;
8. positive, negative, missing, API-error, and relevant truncation tests;
9. generated reference docs and demo/sample anchors;
10. report/action-plan wording.

Follow [Adding a check](adding-a-check.md) and run the validators named in `maturity-goal.md`. Do not begin by adding a card to the report.

## Debugging a surprising result

Trace one `check_id` through the layers:

```text
report row
  → viewmodel `_finding_entry`
  → `ScanResult.findings[]`
  → evaluator binding
  → evaluator
  → normalized evidence key
  → collector
  → API/backend response
```

For a capability headline, trace:

```text
headline sentence
  → `CapabilityRollup.realized_sentence`
  → `engine/rollup.py`
  → capability outcomes
  → findings + entitlement state
```

The right fix is usually at the first layer where the evidence becomes ambiguous, not in the final template.

## Verification commands

```bash
uv run pytest -q -m "not browser"
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run python scripts/validate_flagship_tests.py
uv run python scripts/validate_flagship_meta.py
uv run python scripts/validate_coverage_manifest.py
uv run python scripts/validate_sku_catalog.py
uv run mkdocs build --strict
```

For report changes, also run the browser suite and regenerate the committed sample assets when the repository's design gate requires it.

# DESIGN_V2 — Security License Lens HTML Report (v2)

> Status: implementation contract for the v2 report redesign. Supersedes `DESIGN.md` in full.
> Audience: the engineer implementing the report template. Everything below is binding; anything
> not declared here does not ship. No toolchain is prescribed and none may be introduced: this
> contract describes tokens, type, structure, motion, and accessibility of a static, offline HTML
> artifact only.

## 1. Identity and guardrails

**Identity: "Ink and Verdigris".** A deep green-ink charcoal canvas with a soft verdigris
(oxidized-copper / eucalyptus) accent. Premium, calm, instrument-like. Not blue, not violet,
not neon.

**Retired v1 values (must not appear anywhere in the v2 CSS):** canvas `#0f1114`, accent
`#88b4d8`, surface ramp `#16191d / #1c2025 / #242930 / #2c323b`, borders `#2a3038 / #3a424c`,
text ramp `#f2f4f7 / #b9c0ca / #8a919c`, states `#ff737a / #e2b84b / #67c991 / #96938b`, print
pair `#2c5a7d / #b3261e / #8a5a00 / #1e7a3a / #57534e`. New ramp below replaces them wholesale.

**Forbidden (unchanged from v1, plus one new retirement):**
- No pure black `#000000` canvas or surface fill.
- No violet / purple / pink, no brass or gold hexes (`#b9a06a`, `#cbb683`, `#ddcca8`, `#594818`),
  no saturated navy `#5b9dff` accent, no saturated cyan product accent.
- No glassmorphism (no `backdrop-filter`), no gradient washes of any kind, and specifically no
  `radial-gradient` backdrop and no `color-mix()`.
- No external font, icon package, image asset, chart library, data-URI, or network request of
  any kind.
- No `<img>` element anywhere. **The v1 `workload-icon` `<img>` allowlist is retired in v2.**
  Workloads are named with visible text labels only.
- No blanket radius above 4px; no circles (`50%`) and no pills (`999px`).
- No emoji for metadata or iconography.
- No light-mode screen UI. Screen is always dark; only print inverts to light ink.

## 2. Token palette

Declared once in `:root`, referenced by name everywhere else. Never re-declared.

### 2.1 Screen tokens (dark-first)

| Token | Hex | Role |
| --- | --- | --- |
| `--canvas` | `#0c1210` | Deepest green-ink charcoal page stock |
| `--surface-1` | `#121a17` | Primary surface (sections, findings, filter defaults) |
| `--surface-2` | `#17201d` | Secondary surface (cards, hero body) |
| `--surface-3` | `#1e2925` | Raised surface (open disclosures, elevated panes) |
| `--surface-4` | `#26332e` | Highest surface (focused/active panes, masthead chrome) |
| `--border` | `#233029` | Default 1px rule |
| `--border-strong` | `#31413a` | Strong / emphasis 1px rule |
| `--text-1` | `#eef2ef` | Primary ink |
| `--text-2` | `#b6c2bd` | Secondary ink (labels, meta, section help) |
| `--text-3` | `#85918b` | Tertiary ink (captions, placeholders, faint counts) |
| `--accent` | `#8ad3b8` | Verdigris identity + interaction (measured ≥ 9.5:1 on `--canvas`) |
| `--accent-hover` | `#a5e2ca` | Accent hover |
| `--accent-focus` | `#bdecd9` | Focus ring |
| `--accent-print` | `#145c48` | Print ink for links and identity figures (≥ 7.9:1 on white) |
| `--state-action` | `#f8756b` | Action-required (gap) and error rail/label (≥ 6.5:1 on `--surface-1`) |
| `--state-incomplete` | `#e2a944` | Incomplete (partial) (≥ 8.5:1 on `--canvas`) |
| `--state-ok` | `#4cd07d` | Operational (ok) (≥ 9.5:1 on `--canvas`) |
| `--state-neutral` | `#9aa49e` | Neutral (not-licensed / skipped) (≥ 7:1 on `--canvas`) |
| `--shadow-key` | `0 1px 2px rgba(0,0,0,.55), 0 1px 3px rgba(0,0,0,.2)` | Key elevation for open disclosures / focused panes |
| `--shadow-soft` | `0 4px 12px rgba(0,0,0,.5), 0 2px 6px rgba(0,0,0,.28)` | Soft ambient elevation for hero only |

### 2.2 Print tokens (light inversion)

Screen is always dark; `@media print` inverts to light ink by swapping to these tokens:

| Token | Hex | Role |
| --- | --- | --- |
| `--print-ink` | `#1a1d1b` | Near-black green-ink body text (never `#000000`) |
| `--print-paper` | `#ffffff` | Paper |
| `--print-hero` | `#f0f4f1` | Pale green-tinted hero wash |
| `--print-border` | `#c9cfcb` | Default print rule |
| `--print-border-strong` | `#97a09b` | Strong print rule |
| `--print-action` | `#b3321c` | Print gap/error (≥ 6:1 on white) |
| `--print-incomplete` | `#7c5200` | Print partial (≥ 6.8:1 on white) |
| `--print-ok` | `#1c6e3f` | Print ok (≥ 6.2:1 on white) |
| `--print-neutral` | `#555e59` | Print neutral (≥ 6.7:1 on white) |

Print rules: suppress both shadow tokens; status-marker backgrounds transparent; links and
figures use `--accent-print`; keep `print-color-adjust: exact`; hide technical disclosures and
footer; hero, cards, findings, and constellation protected from page breaks (`break-inside: avoid`).

### 2.3 Usage rules and contrast floors

- **Accent is identity-only.** It colors the logo mark, links, focus rings, selection, the
  posture figure, and the constellation group captions. It never colors a semantic status.
- **Semantic mapping:** `gap` → `--state-action`; `partial` → `--state-incomplete`;
  `ok` → `--state-ok`; `not_licensed` → `--state-neutral`; `skipped` → `--state-neutral`;
  `error` → `--state-action` (rail + label, screen and print, same as gap).
- **Contrast floors (WCAG 2.2 AA), pre-measured:** body text ≥ 4.5:1; large text and non-text
  status indicators ≥ 3:1; accent on canvas ≥ 9.5:1; focus ring against any adjacent surface
  ≥ 3:1; print accent ≥ 7.9:1. The measured ratios are declared in the tables above and are part
  of the contract — do not ship a palette edit without re-measuring.
- **Surface ladder:** `--canvas` → `--surface-1` → `--surface-2` → `--surface-3` → `--surface-4`.
  Every declared token must be consumed by at least one selector. Dead tokens are a violation.

## 3. Typography

System-only, offline-safe. No font files, no external stack.

| Role | Value |
| --- | --- |
| Sans stack | `Segoe UI Variable Text, Segoe UI, ui-sans-serif, system-ui, -apple-system, sans-serif` |
| Mono stack | `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace` |

**Type scale (locked):**

| Role | Size / weight / line-height | Notes |
| --- | --- | --- |
| Display (signature line) | `1.6rem / 700 / 1.15` | Hero opening line only |
| Metric figure | `2rem / 700 / 1.1` | Posture percent; `font-variant-numeric: tabular-nums` |
| Metric figure (secondary) | `1.6rem / 700 / 1.1` | Tiles and metric rows; `tabular-nums` |
| Section heading (h2) | `1.15rem / 600 / 1.3` | Sections A–E |
| Card / finding title (h3) | `1.02rem / 600 / 1.3` | Finding titles, capability names |
| Body | `0.95rem / 400 / 1.55` | Prose |
| Label | `0.78rem / 600 / 1.4` | Meta rows, filter labels |
| Micro-label | `0.72rem / 700 / 1.4` | Uppercase, `0.04em` letter-spacing |

**Heading hierarchy (locked):** exactly one `<h1>` ("Security License Lens" in the masthead);
one `<h2>` per section A–E; `<h3>` for finding titles and capability names. No skipped levels.
The signature opening line is display text in a `<p>`, **not** a heading, so the tree stays
`h1 → h2 → h3`.

**Numeral rules (unchanged from v1):** every metric figure sets `font-variant-numeric:
tabular-nums`; numbers right-align, text left-aligns; mono stack for `check_id`, SKU part
numbers, timestamps, service-plan names, and every numeric column; long tokens wrap with
`overflow-wrap: anywhere`.

## 4. Radius, spacing, layout

- **Base unit: 4px.** Every padding, gap, and inset is a multiple of 4.
- **Spacing stops:** 4, 8, 12, 16, 20, 24, 32, 48. Canonical: section padding `16px 20px`,
  card padding `16px`, finding gap `12px`, section margin `16px`, filter gap `8px`.
- **Radius contract (locked):**
  - `0px` — page sections, hero, tiles, cards, findings, disclosures, constellation frame.
  - `2px` — logo mark, status labels, effort labels, filter buttons.
  - `4px` — focus and active panes. **Maximum radius anywhere.**
  - Forbidden: `8px`, `12px`, `50%`, `999px`.
- **Layout:** desktop 12-column grid, content max-width `1100px`, centered. Breakpoints `900px`
  and `640px` (same collapse behavior as v1).
- **Target sizes:** coarse pointer minimum `44×44px`; fine pointer (`@media (pointer: fine)`)
  minimum `24×24px`.
- **No** `color-mix()`, **no** `radial-gradient` (nor any gradient), **no** `backdrop-filter`,
  **no** blur. Depth is the tonal ladder plus the two pinned shadows on raised layers only.

## 5. Information architecture (A–E, in this order)

The report is a single bounded `<main>` containing five sections, exactly in order A, B, C, D, E.

### A. "Where you stand"

**Signature opening.** The first line of section A is the display line, exact copy:
`Your security investment coming into focus`. It is a `<p>` at display size, `--text-1`.

**Posture figure (data-driven, never hardcoded).** Directly below the opening, the posture
metric binds `capability_rollup.realized_percent` and renders as `<number>% realized`, accent
color, metric-figure size, `tabular-nums`. The value comes **only** from the view model field —
the template contains no literal number. (The `17% realized` in `examples/sample-report` is
illustrative dry-run sample data: `CapabilityRollup(realized_percent=17)`; it is not a constant
anywhere in the template.)

**Rollup sentence.** Beside or below the figure, the rollup sentence binds
`capability_rollup.realized_sentence` (e.g. "5 of 6 still not fully working") at body size,
`--text-2`.

**Rollup counts.** Four to five tiles bind, in order: `you_own` (labeled "You own"),
`fully_working` ("Fully working", `--state-ok` figure), `needs_attention` ("Need attention",
`--state-incomplete` figure), `partly_set_up` ("Partly set up"), `not_licensed`
("Not in your plan", `--state-neutral` figure). Zero values render as `0` — never omitted.

**Critical rail.** When `has_exposed` is true or any gap/error finding exists, a 3px
`--state-action` left rail lists the exposed/gap check titles (bound from `exposed_check_ids`
resolved against findings), capped at three with "and N more" trailing text.

### B. "What you're paying for"

**Purpose.** Show the entitlements the tenant already pays for and what each one maps to.

- **Owned SKUs strip:** one row per `subscribed_skus` entry — SKU name and part number in mono,
  license count right-aligned `tabular-nums`. Compact table, `--surface-2`.
- **Capability field (signature visualization):** the constellation, specified in section 6,
  renders `capability_outcomes` grouped by workload. It is the section's centerpiece.
- **Capability detail list:** one `article` per `capability_summaries` entry: `plain_name`
  title, Microsoft name, matched SKUs and service plans (mono), "What it does" (summary
  fields), "Why it matters" (`why_it_matters`), "If left off" (`if_unused`), and the
  capability's status label from its `capability_outcomes` entry. Status marker per section 9.

### C. "What matters most"

- Renders `moves` (the `TopMove` list), at most the top 3, as an `<ol>`.
- Each item: bold `title`, effort label (bound `effort_label`, e.g. "~a few hours"), a "Why"
  line (`why`), and an action line (`customer_next_step`). `deep_link`, when present, renders as
  the visible link "Open the admin page" — text link, accent color, no fake button.
- Order is rank: the list order from the model is authoritative; the UI must not re-sort.

### D. "Why LicenseLens believes this"

Per-finding belief block. Every finding renders as a full-width `article` with a 3px left status
rail and a header (status marker + title + meta row: severity, effort, scope, workload,
confidence, evaluation mode). The body is the **six-slot belief block**, always in this order,
each slot with a visible bold label prefix:

| Slot | Label | Binding (in fallback order) |
| --- | --- | --- |
| 1 | Expected | `summary`, then `customer_summary` |
| 2 | Observed | `customer_summary`, then evidence-derived summary line |
| 3 | Why it matters | `impact_label` + `severity` label |
| 4 | Recommended action | `customer_next_step`, then `remediation` |
| 5 | Evidence | `data_sources` + `evidence` keys inside the disclosure (section 7) |
| 6 | Admin destination | `deep_link` as the visible link "Open the admin page" |

Slot 5's detail lives in a native `<details class="tech">` disclosure holding the evidence
table and `source_references`. Empty optional fields render "Not reported" — never crash.

### E. "Explore everything"

- **Search:** `<input type="search">`, visible label "Search findings", `autocomplete="off"`
  `spellcheck="false"`. Case-insensitive substring match over finding text only. Never regex
  against user input, never render matches back as HTML.
- **Filter groups:** one `role="group"` (with `aria-label`) per facet — status, severity,
  confidence, evaluation mode, pack, workload. Within a group selection is OR (multi-toggle);
  across groups facets compose with AND. Every button exposes `aria-pressed`. A "Clear all"
  control resets all groups and the search box.
- **Sort:** a native `<select>` with a visible label. Options (fixed): "Rank (default)",
  "Severity", "Effort", "Title A–Z". Default is model rank order; only "Title A–Z" is a
  locale-insensitive byte sort — all others are deterministic and documented here.
- **Counts:** result count is `role="status"` `aria-live="polite"`, right-aligned, `tabular-nums`.
- **Pagination:** prev/next buttons, "Page N of M", page-size select 25/50/100; hidden when zero
  results. Page changes preserve focus on the pager.

## 6. Signature visualization: the capability constellation

A deterministic field of capability points. Not a graph — explicitly no node-link topology.

**Data.** One point per `capability_outcomes` entry. Point color binds the entry's `status`
(see semantic mapping, section 2.3). Workload grouping derives from the entry's
`related_check_ids` resolved against `Finding.workload`; a capability spanning workloads uses
the workload of its first related check, in the model's own order.

**Determinism (no randomness, no physics, no simulation).**
1. Workload groups appear in the fixed `Workload` enum order:
   `identity, defender, sentinel, purview, endpoint, exchange, collaboration, teams,
   power_platform, power_bi, intune, azure, general`.
2. Within a group, points are sorted by `plain_name` ascending (byte sort, locale-insensitive).
3. A point's position is a pure function of `(group index, point index, group size)`: groups
   render as columns in a CSS grid; within a column, points stack top-to-bottom in sorted order
   with fixed `12px` spacing. Identical input always yields identical pixels.

**Geometry.** Each point is a 10×10px square (2px radius, `--canvas` center core with a 2px
status-color fill), with its `plain_name` as a visible text label directly beneath it
(`0.78rem`, `--text-2`, wrapping allowed, `max-width` per column). Status color is never the
only channel: the point's shape is uniform, so each point's label is always visible, and each
group carries a caption (workload plain name, micro-label) plus a tiny legend mapping color to
the six statuses with words.

**What it must not be:** no edges, no lines, no loops, no links between points, no random
jitter, no animation library, no canvas element, no images — plain HTML/CSS grid (or inline
SVG using `currentColor` for the point fills) laid out per the deterministic rule above.

**Motion:** points fade+settle once (section 8); under `prefers-reduced-motion` the final state
renders instantly.

## 7. Progressive disclosure

Three levels, always in this order, never all at once:

1. **Summary** — finding title, status marker, meta row, slot 1–2 prose (Expected / Observed).
2. **Explanation** — slots 3–4 (Why it matters / Recommended action) plus the admin link.
3. **Evidence** — the `<details class="tech">` disclosure: evidence keys, `data_sources`,
   `source_references`, technical table.

The disclosure is a native `<details>` with a text summary ("Technical evidence"), caret
glyph (decorative, `aria-hidden`), closed state dashed border `--surface-1`, open state solid
border `--surface-3` + `--shadow-key`. Native keyboard/AT behavior; state conveyed via `open`.

## 8. Motion contract

Motion animates **information arriving**, never decoration. Allowed animations, complete list:

| Animation | Target | Timing |
| --- | --- | --- |
| Posture resolve | Posture figure: digits masked (`opacity: 0`, `translateY(8px)`) → visible | `700ms ease-out` once on load (within the required 500–1000ms window) |
| Section reveal | Sections A–E and finding articles: `opacity` + `translateY(8px)` → final, staggered `40ms` per sibling, capped | `300ms ease-out` each, once |
| Constellation settle | Points fade in column by column, in the deterministic order above | `400ms ease-out`, `60ms` stagger per column |
| Interactive transitions | Filter/search/pagination color, border, background only | `≤150ms` |
| Disclosure caret | Rotate on open/close | `≤150ms` |

Rules: only `transform` and `opacity` animate position/appearance; interactive states animate
non-layout properties only; no ambient, looping, or ornamental motion; nothing animates while
the user scrolls or types.

`@media (prefers-reduced-motion: reduce)`: all transitions and animations collapse to the
instant final state (duration `0s`, iteration count `1`, no `translateY` offset ever applied).
Posture digits, constellation, and section reveals appear fully resolved immediately.

## 9. Retained v1 rules (still mandatory)

1. **Inline SVG only.** Every status glyph is an inline `<svg viewBox="0 0 24 24">` using
   `currentColor`, with `aria-hidden="true" focusable="false"`, always beside a visible text
   word (the PRESENTATION word from `STATUS_PLAIN_LABELS`, never a raw enum). The six glyphs
   keep v1's locked geometry and remain pairwise distinct: gap = chevron-alert, partial =
   half-fill, ok = check-ring, not_licensed = slash-circle, skipped = dash, error =
   triangle-alert.
2. **No external anything.** No fonts, CDNs, images, chart libraries, data-URIs, network
   requests. No `<img>` at all (workload-icon exception retired).
3. **No emoji** for metadata, statuses, or labels. Meta values are text keys with text values.
4. **Status is never color-only.** Label + unique glyph geometry + color, everywhere —
   including constellation points (label always visible).
5. **Keyboard accessible.** Every interactive element has hover, active, and `:focus-visible`
   (2px `--accent-focus` outline, 2px offset). Minimum target sizes per section 4.
6. **ARIA contracts.** Exactly one `<main>`; exactly one `<h1>`; heading levels never skip;
   filter buttons expose `aria-pressed`; result count is a polite live region; filter groups
   are `role="group"` with `aria-label`; nav and pagination use `<nav aria-label>`.
7. **Forced colors.** Glyphs and constellation fills use `currentColor` so they stay distinct
   under `forced-colors: active`; the v1 forced-colors block's spirit is preserved.
8. **Print inverts to light** (section 2.2): both shadow tokens suppressed, status labels
   transparent-backed with contrast-safe print state colors, disclosures and footer hidden.
9. **Null/empty fields** render without crash: omit the row or show "Not reported" /
   "None reported".
10. **Accent discipline.** Accent colors identity and interaction only; semantic states use
    state tokens only; error shares the gap rail color on screen and in print.

## 10. Definition of done

- Every color in the shipped CSS is a declared token from section 2; no literal hex escapes the
  tables above except inside the `:root` block.
- Posture figure binds `capability_rollup.realized_percent`; searching the template for `17`
  yields no literal percentage constant.
- No `radial-gradient`, no `color-mix(`, no `backdrop-filter`, no `border-radius` above `4px`,
  no `<img>`, no external URL, no emoji.
- Constellation renders identically for identical input (deterministic sort + placement).
- Reduced-motion renders the final state instantly.
- Screen is dark, print is light; both pass the section 2.3 contrast floors.

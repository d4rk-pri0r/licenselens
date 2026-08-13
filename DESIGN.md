# Security License Lens — Design System

This file is the implementation contract for the static HTML report. Every color, type choice, spacing value, component primitive, state, and motion rule used in the report traces back to a declaration here. It is authored as an extraction of the existing report, not a greenfield proposal: the eight components below map one-to-one onto the report's rendered structure (metric tiles, status badges/markers, capability cards, the "Top things to do first" list, findings, the status/workload filter bar, the native `<details>` disclosures, and the two technical reference tables).

## Atmosphere & Identity

Security License Lens is a **read-only security audit**, not a marketing page. The report answers one question — *which protections do you already pay for, and which are still off?* — and its surface must project the same calm, skeptical authority as a printed config ledger or a vendor security review.

The identity is **warm, low-light, and editorial**: near-black warm-neutral surfaces with a crisp 1px border grid, and a single restrained violet accent reserved for product identity and interaction. Nothing is decorative for its own sake; every mark on the page either carries a status or explains an entitlement.

**Rejected directions (non-negotiable):**
- No cool-blue accent and no blue-to-violet "AI" gradient wash.
- No frosted / backdrop-blur translucency; depth is achieved purely through tonal shift and borders.
- No ornamental or ambient motion; motion only signals a state change or an affordance.
- No downloaded font files and no external asset hosts; the report renders fully offline.
- No icon library and no image/noise assets; symbols are typographic (carets, bullets, dots).

## Color

All 16 tokens are declared once here. Reference them by name elsewhere; never re-declare a value.

| Token | Hex | Role |
| --- | --- | --- |
| `--canvas` | `#11110f` | Deepest page background |
| `--surface-1` | `#171714` | Primary surface (sections, cards, tables) |
| `--surface-2` | `#1d1d19` | Secondary / elevated surface (raised cards, disclosures) |
| `--surface-3` | `#24231f` | Highest elevation surface (overlays, focused panes) |
| `--border` | `#34332d` | Default 1px border |
| `--border-strong` | `#494840` | Strong / emphasis 1px border |
| `--text-1` | `#f1f0ea` | Primary text |
| `--text-2` | `#b2b0a7` | Secondary text (labels, meta, section help) |
| `--text-3` | `#85827a` | Tertiary text (captions, placeholders, faint counts) |
| `--accent` | `#9b8cff` | Product accent (base) |
| `--accent-hover` | `#b0a4ff` | Product accent (hover) |
| `--accent-focus` | `#c7beff` | Product accent (focus ring) |
| `--state-action` | `#ff737a` | Action-required (gap) |
| `--state-incomplete` | `#e2b84b` | Incomplete (partial) |
| `--state-ok` | `#67c991` | Operational (ok) |
| `--state-neutral` | `#96938b` | Neutral (not-licensed / skipped / error) |

**Accent usage rule.** `--accent` (with `--accent-hover` / `--accent-focus`) is used *only* for: product identity (logo mark), active controls, links, focus indication, and the realized-percentage figure in the hero rollup. It is never used to color a semantic problem state — a gap, a partial, an ok, or a neutral result always uses its dedicated state token.

**Semantic state mapping.** `gap → --state-action`; `partial → --state-incomplete`; `ok → --state-ok`; `not_licensed`, `skipped`, and `error → --state-neutral`. The neutral token is the sole exception that also doubles as the calm background tint for not-licensed / skipped / error rows, badges, and rails.

**Depth strategy.** Elevation is a tonal ladder plus a crisp 1px border — never a drop shadow, never a frosted blur. The only permitted gradient anywhere is a single faint two-radial-gradient vignette on `--canvas` (see the depth section below).

## Typography

System-only, offline-safe. No font files are downloaded and no external font stack is referenced.

| Role | Value |
| --- | --- |
| Sans stack | `Segoe UI Variable Text, Segoe UI, ui-sans-serif, system-ui, -apple-system, sans-serif` |
| Mono stack | `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace` |

**Mono usage.** Use the mono stack for: technical IDs (`check_id`, SKU part numbers), timestamps, service-plan names, and every numeric column. These are identifiers and measurements, not prose — mono marks them as machine data.

**Tabular numerals.** Every numeric and metric figure (rollup counts, units, percentages, effort figures) sets `font-variant-numeric: tabular-nums` so columns align and counts do not jitter on re-render.

**Alignment.** Numbers right-align; text left-align. A numeric column in a table is right-aligned against its header; a label or title column stays left-aligned.

**Scale (recommended, not a locked token).** Metric figure `1.6rem/700`; section heading `1.15rem/600`; card title `1.02rem/600`; body `0.92–0.95rem`; caption/label `0.78rem`; micro-label `0.72rem` uppercase with `0.04em` letter-spacing. Line height `1.55` for body. This scale is guidance; the four locked rules above (stacks, mono scope, tabular-nums, alignment) are canonical.

## Spacing & Layout

- **Base unit: 4px.** Every padding, gap, and inset is a multiple of 4.
- **Desktop grid: 12 columns**, content max-width **1100px**, centered with responsive gutters.
- **Breakpoints: 900px and 640px.** 900px collapses the 12-column grid to fewer fluid columns (cards wrap to two-up then one-up); 640px is the single-column handset layout where tiles run two-per-row.

**Spacing stops** (multiples of the 4px base): 4, 8, 12, 16, 20, 24, 32, 48. Canonical choices: section padding `16px 20px`, card padding `16px`, card/finding gap `12px`, section margin `16px`, filter-pill gap `8px`.

The metric-tile band and the capability-card band are both 12-column CSS grid layouts: tiles at `minmax(150px, 1fr)` per column, cards at `minmax(280px, 1fr)`, so both reflow on the grid rather than with bespoke media queries.

## Components

Eight primitives. Each lists Structure, Variants, Spacing, States, Accessibility, Motion, and Layout.

### 1. Summary metric

- **Structure:** a large numeric figure (`.n`) above a label (`.l`) with an optional uppercase micro-sub-label. Inside a bordered surface tile.
- **Variants:** neutral figure (default `--text-1`); accent figure (the realized-percentage figure, `--accent`); status figure (`--state-ok` / `--state-incomplete` for the rollup counts).
- **Spacing:** tile padding `16px`; figure-to-label gap `4px`; tile gap `12px`.
- **States:** static (non-interactive); no hover/active/focus behavior.
- **Accessibility:** the number is text, not an image; the label + sub-label carry meaning, so the figure is never color-only. `tabular-nums` on the figure.
- **Motion:** none.
- **Layout:** one tile per grid column; 12-column grid, tiles `minmax(150px, 1fr)`.

### 2. Status marker

- **Structure:** a compact label with a geometric glyph. Two shapes: **dot** (8px filled circle before an inline status word, used in capability cards) and **pill badge** (rounded full-width container with status text, used in findings and tables).
- **Variants:** four status variants — action-required, incomplete, operational, neutral — each binding a label, a glyph geometry, and a state token. Neutral also covers not-licensed / skipped / error with their own words but the same visual token.
- **Spacing:** dot-to-text gap `8px`; pill padding `4px 10px`; badge font `0.75rem/700`.
- **States:** static label; it is never itself a control.
- **Accessibility:** status is encoded by **label + geometry + color** — the glyph (filled dot vs. text) and the word differ, so the color is redundant, never the only channel. Grayscale-safe.
- **Motion:** none.
- **Layout:** inline-flex; the dot marker sits above a card title, the pill sits inline in a finding header or table cell.

### 3. Capability card

- **Structure:** `article` surface: status marker (dot) at top, plain-name title, "Microsoft name" line, then labeled rows — what it does, why it matters, if it is not set up, included-through SKU(s), matching service-plan(s).
- **Variants:** by status — the variant is carried by the dot marker + the card's surface elevation, not by a recolored border. All statuses share one card shape.
- **Spacing:** padding `16px`; title-to-sub `8px`; row gap `12px`; label prefix separated by a full stop and styled `--text-2/600`.
- **States:** default surface only; the card itself is non-interactive (no hover lift).
- **Accessibility:** SKU and service-plan names render in the mono stack; long plan names wrap safely. Label prefixes ("What it does.", "Why it matters.") are visible text, not icons.
- **Motion:** none.
- **Layout:** card grid `minmax(280px, 1fr)` on the 12-column grid, gap `12px`.

### 4. Action item

- **Structure:** an ordered-list item in the ranked "Top things to do first" list: bold title, an optional effort badge, a "why" line, and a "Suggested next step" line.
- **Variants:** none by status; ordering is by rank (the `<ol>` semantics), and the effort badge is the only modifier.
- **Spacing:** item gap `16px`; title-to-detail `8px`; badge left margin `8px`.
- **States:** non-interactive text; no hover/active/focus.
- **Accessibility:** the `<ol>` preserves rank for screen readers and in print; "Next step" is bolded prose, not a button — no affordance is faked.
- **Motion:** none.
- **Layout:** full content width, left-aligned list numbering.

### 5. Finding

- **Structure:** `article` with a 3px left status rail, a badge + title header, a meta row (severity, effort, blast radius, workload), a customer summary, a suggested next step, and an embedded technical disclosure.
- **Variants:** six — gap, partial, ok, not-licensed, skipped, error — each driving the rail color and badge variant (skipped and error share the neutral rail).
- **Spacing:** padding `16px`; finding gap `12px`; header-to-meta gap `8px`.
- **States:** default only; the finding is not a control (the disclosure inside is).
- **Accessibility:** the 3px rail is geometry (width + position), the badge carries the word, and the rail carries the state token — three channels, never color-only. Meta glyphs are typographic bullets, not emoji.
- **Motion:** none on the container.
- **Layout:** full-width stacked list, one finding per row; rail renders on the left edge.

### 6. Filter group

- **Structure:** a horizontal wrapping bar of pill buttons with a trailing "Showing N of N" count. Two groups exist: a status filter and a workload filter, each ending with an "All" reset.
- **Variants:** status filter and workload filter (identical anatomy, different data).
- **Spacing:** pill gap `8px`; pill padding `4px 12px`; bar margin-bottom `12px`.
- **States:** default (`--surface-1` fill, `--text-2`); hover (`--border` → accent border, text → `--text-1`); active (accent-tinted fill, accent border, accent text); `:focus-visible` (2px accent outline, 2px offset). Keyboard-toggleable buttons.
- **Accessibility:** active state is both the tinted fill and the border — not color-only; `aria-pressed`/selected state is exposed on the active pill.
- **Motion:** `background`, `color`, and `border-color` transitions, ≤150ms; `transform`/`opacity` only — no layout animation.
- **Layout:** flex-wrap row; the count is pushed right with `margin-left: auto`.

### 7. Disclosure (native `<details>`)

- **Structure:** a native `<details class="tech">` with a `<summary>` caret + label, and a body of evidence / technical tables.
- **Variants:** inline disclosure (per finding: "Evidence and Microsoft admin page") and the full technical reference disclosure (SKU + finding tables).
- **Spacing:** padding `12px 16px`; summary-to-body gap `12px` when open.
- **States:** closed (dashed border, `--text-2` summary); open (solid border, `--text-1` summary); summary hover (text → `--text-1`); summary `:focus-visible` (2px accent outline, 2px offset).
- **Accessibility:** native `<details>/<summary>` semantics give free keyboard + AT toggling; the caret is decorative typography (a rotated `▸`), and state is exposed via the element's own `open` attribute, not the glyph alone.
- **Motion:** the caret rotates via `transform` ≤150ms; the disclosure itself does not animate open/close.
- **Layout:** full-width; the inline variant nests inside a finding, the technical variant spans the page bottom.

### 8. Technical table

- **Structure:** a bordered `<table>` with a muted uppercase header row and body rows; two instances — "Subscribed SKUs" (part number, status, units, service plans) and the finding reference table (status, check ID, title, workload, severity).
- **Variants:** by content, not by shape; the SKU table and finding table share one table style.
- **Spacing:** cell padding `12px 8px`; `1px` bottom border per row (no vertical rules).
- **States:** static; header row non-interactive.
- **Accessibility:** `<th scope>` on headers; numeric columns right-aligned with `tabular-nums`; IDs, part numbers, timestamps, and plan names in the mono stack; long identifiers wrap safely.
- **Motion:** none.
- **Layout:** full-width, `border-collapse: collapse`; on the handset breakpoint the table scrolls within its disclosure rather than squashing columns.

## Motion & Interaction

Motion is **CSS-only**, **≤150ms**, and limited to `transform` and `opacity` (plus the non-layout color/border properties on filter pills). No keyframe loops, no staggered reveals, no scroll-triggered effects, no transitions on layout properties (width, height, margin, top/left).

- `prefers-reduced-motion: reduce` disables **all** transitions and the caret rotation.
- Every interactive element has **hover + active + `:focus-visible`**. The `:focus-visible` treatment is a **2px `--accent-focus` outline with a 2px offset**.
- Minimum interactive target is **24×24px** (filter pills, disclosure summaries).
- The only animated affordances are: filter-pill hover/active tint, disclosure caret rotation, and focus-ring fade. Each maps to a real state change — nothing animates to "look alive".

## Depth & Surface

Elevation is a **tonal ladder**, not a shadow system. Four levels, warm and near-black, each step a small lightness gain:

`--canvas` (deepest) → `--surface-1` (sections/cards) → `--surface-2` (raised cards, disclosures) → `--surface-3` (overlays, focused panes).

Edges are carried by **crisp 1px borders**: `--border` for quiet separation, `--border-strong` to lift a pane. Raised emphasis (the hero rollup, an open disclosure) combines a higher surface token with a strong border — never a drop shadow, never a frosted blur.

The single permitted background flourish is a **faint two-radial-gradient vignette on `--canvas`**: two soft, very-low-opacity warm radial glows behind the header, giving the page a subtle lit-from-above feel without any translucency or noise. Surfaces and borders are opaque; only this vignette uses a gradient.

Status rails (the finding's 3px left edge) and status badges supply all non-shadow emphasis — color is reserved for meaning, borders for structure.

## Accessibility Constraints & Accepted Debt

Target is **WCAG 2.2 AA**, verified against the declared palette.

- **Contrast floors:** body text ≥ **4.5:1**; large text (≥ `1.6rem` metrics, headings) ≥ **3:1**; non-text and status indicators ≥ **3:1**.
- **Status is never color-only.** Every status uses label + geometry + color (word, dot/pill/rail shape, and hue together). The dot marker and the 3px rail remain distinguishable in grayscale.
- **Print inverts to light ink.** The printed page uses a light background with dark text; status rails and status symbols must hold ≥ **4.5:1** grayscale-safe contrast on white. The technical disclosure and footer are hidden in print; tiles/cards/findings avoid page breaks.
- **Long tokens wrap safely.** Technical IDs, SKU part numbers, and service-plan names use the mono stack with safe wrapping (`overflow-wrap: anywhere` / `word-break` on identifier cells) so a long plan name cannot overflow its card or cell.
- **Focus is always visible.** 2px accent outline + 2px offset on every interactive element via `:focus-visible`.
- **Reduced motion** is respected everywhere (see the motion section above).

**Accepted debt (deliberate, reviewed):**

- (a) **English-only UI** — no i18n; all report copy is authored in English.
- (b) **Modern-browser floor for CSS `color-mix()`** — accent-tinted fills (active pills, hero tint) rely on `color-mix(in srgb, …)`, so legacy engines that lack it degrade to flat fills rather than breaking layout.
- (c) **No `general` workload filter** — the filter bar omits a `general` toggle because no current check uses the `general` workload; adding it would render a dead control.

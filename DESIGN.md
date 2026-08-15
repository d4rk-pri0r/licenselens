# Security License Lens: Design System

This file is the implementation contract for the static HTML report. Every color, type choice, spacing value, component primitive, state, and motion rule used in the report traces back to a declaration here. The report is a layered enterprise-XDR security console: dense, cool-charcoal, instrument-like, and offline-first.

**Anti-churn freeze.** After this redesign lands, future visual changes edit tokens and primitives only. Do not rewrite this contract wholesale again.

## Atmosphere & Identity

Security License Lens is a read-only security audit, not a marketing page. It answers one question: which protections do you already pay for, and which are still off?

The identity is a **layered enterprise security console**. Cool-charcoal surfaces step through five tonal levels. Depth comes from the surface ramp plus two pinned shadow tokens on raised/focused layers only. One restrained cool steel/ice-blue accent carries identity and interaction. Semantic red/amber/green/neutral remain outcome-only and never double as branding.

**Rejected directions (non-negotiable):**
- No pure black `#000000` canvas or surface fill.
- No brass identity tokens (`#b9a06a`, `#cbb683`, `#ddcca8`, `#594818`).
- No violet/purple/pink AI gradient, and no navy `#5b9dff` or saturated cyan product accent.
- No glassmorphism, backdrop-blur, neon/cyberpunk, or decorative glow stacks.
- No external font, CDN, icon package, image asset, data-URI, or network request — **except** the narrow `workload-icon` primitive below (todo-15 checksum-pinned local hashed images only).
- No external/embedded-file SVG. Inline `<svg>` macros are allowed when they use `currentColor` and `aria-hidden="true"` beside a visible text label. The `workload-icon` exception may use local hashed `<img>` files (SVG/PNG) from the offline vendor allowlist; never inline vendor SVG into HTML/JS.
- No blanket pill or radius above 4px. Circles and 999px pills are forbidden as component shapes.
- No emoji iconography and no copied vendor branding, logos, product names, exact vendor tokens, or trade dress — **except** the narrow `workload-icon` primitive below for product-identification marks only (never LicenseLens branding, never status meaning).
- No light-mode UI feature. The screen is always dark; only print inverts to light ink.
- Shadows are exactly the two pinned tokens below, applied only to raised/focused/interactive layers. Ordinary records stay tonal + 1px rules with no shadow.

## Color

All tokens are declared once here. Reference them by name elsewhere; never re-declare a value.

| Token | Hex / value | Role |
| --- | --- | --- |
| `--canvas` | `#0f1114` | Deepest cool-charcoal page stock |
| `--surface-1` | `#16191d` | Primary surface (sections, findings, filter defaults, disclosures default) |
| `--surface-2` | `#1c2025` | Secondary surface (cards, hero body) |
| `--surface-3` | `#242930` | Raised surface (open disclosures, elevated panes) |
| `--surface-4` | `#2c323b` | Highest surface (focused/active panes, header chrome) |
| `--border` | `#2a3038` | Default 1px rule |
| `--border-strong` | `#3a424c` | Strong / emphasis 1px rule |
| `--text-1` | `#f2f4f7` | Primary ink |
| `--text-2` | `#b9c0ca` | Secondary ink (labels, meta, section help) |
| `--text-3` | `#8a919c` | Tertiary ink (captions, placeholders, faint counts) |
| `--accent` | `#88b4d8` | Cool steel/ice-blue identity + interaction |
| `--accent-hover` | `#a3c7e4` | Accent hover |
| `--accent-focus` | `#b8d6ee` | Focus ring |
| `--accent-print` | `#2c5a7d` | Print ink for links and identity figures |
| `--state-action` | `#ff737a` | Action-required (gap) and error rail/label |
| `--state-incomplete` | `#e2b84b` | Incomplete (partial) |
| `--state-ok` | `#67c991` | Operational (ok) |
| `--state-neutral` | `#96938b` | Neutral (not-licensed / skipped) |
| `--shadow-key` | `0 1px 2px rgba(0,0,0,.5), 0 1px 3px rgba(0,0,0,.18)` | Tight key elevation for focused panes / open disclosures |
| `--shadow-soft` | `0 4px 12px rgba(0,0,0,.45), 0 2px 6px rgba(0,0,0,.25)` | Soft ambient elevation for hero rollup only |

**Accent usage rule.** `--accent` (with hover/focus/print) is identity-only. It colors the logo mark, links, focus rings, selection, and measurement emphasis in the hero. It never colors a semantic problem state.

**Semantic state mapping.**
- `gap` → `--state-action`
- `partial` → `--state-incomplete`
- `ok` → `--state-ok`
- `not_licensed` → `--state-neutral`
- `skipped` → `--state-neutral`
- `error` → `--state-action` for both label and left rail on screen and in print (aligned with gap)

**Contrast floors.**
- Screen accent `#88b4d8` on `#0f1114` ≥ 4.5:1
- Focus `#b8d6ee` against adjacent surfaces ≥ 3:1
- Print accent `#2c5a7d` on white ≥ 4.5:1
- Body text ≥ 4.5:1; large text ≥ 3:1; non-text status indicators ≥ 3:1

**Depth strategy.** Elevation is a five-step cool-charcoal tonal ladder plus the two pinned shadows on raised layers only. Never a generic drop-shadow card stack. Never blur. Never gradient washes.

## Typography

System-only, offline-safe. No font files are downloaded and no external font stack is referenced.

| Role | Value |
| --- | --- |
| Sans stack | `Segoe UI Variable Text, Segoe UI, ui-sans-serif, system-ui, -apple-system, sans-serif` |
| Mono stack | `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace` |

Four canonical rules (locked):

1. **Mono scope.** Use the mono stack for technical IDs (`check_id`, SKU part numbers), timestamps, service-plan names, and every numeric column.
2. **Tabular numerals.** Every metric figure sets `font-variant-numeric: tabular-nums`.
3. **Alignment.** Numbers right-align; text left-align.
4. **No external font.** Only the two system stacks above.

**Scale (recommended).** Metric figure `1.6rem/700` (hero posture may use `2rem/700`); section heading `1.15rem/600`; card title `1.02rem/600`; body `0.92`–`0.95rem`; caption/label `0.78rem`; micro-label `0.72rem` uppercase with `0.04em` letter-spacing. Line height `1.55` for body.

## Spacing & Layout

- **Base unit: 4px.** Every padding, gap, and inset is a multiple of 4.
- **Desktop grid: 12 columns**, content max-width **1100px**, centered with responsive gutters.
- **Breakpoints: 900px and 640px.** 900px collapses the 12-column grid; 640px is the single-column handset layout.

**Spacing stops:** 4, 8, 12, 16, 20, 24, 32, 48. Canonical choices: section padding `16px 20px`, card padding `16px`, card/finding gap `12px`, section margin `16px`, filter-button gap `8px`.

**Radius contract (locked):**
- **0px:** page sections, hero, tiles, cards, findings, tables, disclosures, critical rail.
- **2px:** logo mark, status labels, effort labels, filter buttons, glyph containers.
- **4px:** focus and active panes. Maximum radius anywhere.
- **Forbidden:** 8px, 12px, 50% (circle), 999px (pill).

**Target sizes (locked):**
- Touch / coarse pointer: minimum interactive target **44×44px**.
- Fine pointer (`@media (pointer: fine)`): minimum **24×24px**.

## Components

Eight primitives. Each lists Structure, Variants, Spacing, States, Accessibility, Motion, and Layout. Status is always **label + geometry + color**.

### 1. Summary metric

- **Structure:** large numeric figure above a label, optional micro-sub-label, inside a ruled 0px-radius tile.
- **Variants:** neutral figure (`--text-1`); accent figure (realized %, `--accent`); status figure for attention counts.
- **Spacing:** tile padding `16px`; figure-to-label gap `4px`; tile gap `12px`.
- **States:** static.
- **Accessibility:** number is text; label carries meaning; `tabular-nums`.
- **Motion:** none.
- **Layout:** 12-column grid, tiles `minmax(150px, 1fr)`.

### 2. Status marker

- **Structure:** compact 2px-radius label with an inline SVG glyph + visible status word.
- **Six named glyphs (locked geometry):**
  - `gap` → **chevron-alert** (filled chevron/alert mark)
  - `partial` → **half-fill** (half-filled square/ring)
  - `ok` → **check-ring** (ring with check)
  - `not_licensed` → **slash-circle** (circle with slash; must not match `ok`)
  - `skipped` → **dash** (horizontal dash bar)
  - `error` → **triangle-alert** (warning triangle)
- **SVG rules:** inline only; single 24×24 viewBox; consistent stroke width; `fill="currentColor"` / `stroke="currentColor"`; `aria-hidden="true"` and `focusable="false"`; visible PRESENTATION word remains the accessible name.
- **Variants:** six statuses binding label + unique glyph + state token.
- **Spacing:** glyph-to-text gap `8px`; label padding `4px 10px`; label font `0.75rem/700`.
- **States:** static label; never itself a control.
- **Accessibility:** never color-only; geometry unique across all six; grayscale-safe via word + shape; forced-colors keeps glyphs via `currentColor`.
- **Motion:** none.
- **Layout:** inline-flex in finding headers, capability cards, and tables.

### 3. Capability card

- **Structure:** `article` surface with 0px radius and 1px rule: status marker at top, plain-name title, Microsoft name, labeled rows (what it does, why it matters, if unused, SKUs, service plans).
- **Variants:** by status via glyph + optional surface elevation, not recolored borders.
- **Spacing:** padding `16px`; title-to-sub `8px`; row gap `12px`.
- **States:** default surface only; non-interactive.
- **Accessibility:** SKU/plan names mono; long names wrap; label prefixes are visible text.
- **Motion:** none.
- **Layout:** card grid `minmax(280px, 1fr)`, gap `12px`. Surface: `--surface-2`.

### 4. Action item

- **Structure:** ordered-list item: bold title, optional effort label, why line, action line, cool-blue index.
- **Variants:** none by status; order is rank.
- **Spacing:** item gap `16px`; title-to-detail `8px`.
- **States:** non-interactive text.
- **Accessibility:** `<ol>` preserves rank; action is bolded prose, not a fake button.
- **Motion:** none.
- **Layout:** full content width.

### 5. Finding

- **Structure:** full-width ruled `article` with 3px left status rail, status marker + title, meta row (severity, effort, scope, workload), customer summary, next step, native technical disclosure. 0px radius.
- **Variants:** six statuses drive rail color and marker. Error rail uses `--state-action` on screen and in print (same as gap).
- **Spacing:** padding `16px`; finding gap `12px`; header-to-meta gap `8px`.
- **States:** default; disclosure inside is the control.
- **Accessibility:** rail + word + glyph; meta is text keys, not emoji.
- **Motion:** none on the container.
- **Layout:** full-width stacked list. Surface: `--surface-1`.

### 6. Filter group (compound)

- **Structure:** a labeled wrapping bar of segmented rectangular buttons (2px radius). Each group owns one facet (status, severity, confidence, evaluation mode, profile, workload). Within a group selection is **OR** (multi-select toggle); across groups facets compose with **AND**. A trailing **Clear all** control resets every group and the search box.
- **Spacing:** button gap `8px`; button padding sized to hit 44px touch / 24px fine-pointer targets; group gap `12px`; group label is a muted uppercase micro-label.
- **States:** default (`--surface-1`, `--text-2`); hover (accent border/text via `--accent-hover`); active (accent rule + accent text on `--surface-2`); `:focus-visible` 2px `--accent-focus` outline, 2px offset.
- **Accessibility:** each group is `role="group"` with an `aria-label`; every button exposes `aria-pressed`; result count is `role="status"` `aria-live="polite"`. Active is never color-only.
- **Motion:** color/border/background ≤150ms.
- **Layout:** flex-wrap; count `margin-left: auto`.

### 7. Disclosure (native `<details>`)

- **Structure:** native `<details class="tech">` with summary caret + label and evidence/table body. 0px radius.
- **States:** closed (dashed border, `--surface-1`); open (solid border, `--surface-3`, `--shadow-key`); summary hover/focus-visible as above.
- **Accessibility:** native keyboard/AT; caret decorative; state via `open`.
- **Motion:** caret rotate via transform ≤150ms.
- **Layout:** full-width; inline in findings or full technical section.

### 8. Technical table

- **Structure:** bordered `<table>` with muted uppercase header row and body rows.
- **Spacing:** cell padding `12px 8px`; 1px bottom rule per row.
- **States:** static.
- **Accessibility:** `<th scope>`; numeric columns right-aligned with `tabular-nums`; mono IDs; long identifiers wrap; status labels use PRESENTATION words, not raw enum values.
- **Motion:** none.
- **Layout:** full-width; handset tables scroll inside the disclosure.

### 9. App shell

- **Structure:** fixed header (brand + tenant meta) and a fixed workload navigation strip; a single bounded `<main>` is the only vertical scroll owner. `body` is `height:100vh; overflow:hidden; display:flex; flex-direction:column`; header/nav are `flex:0 0 auto`; `main` is `flex:1 1 auto; overflow-y:auto`.
- **States:** header/nav static; `main` scrolls; section anchors carry `scroll-margin-top` equal to the fixed chrome height so hash-deep links are not occluded.
- **Accessibility:** nav is `<nav aria-label="Workload navigation">`; the active tab exposes `aria-current="page"`; anchors target `#findings` and per-finding `#finding-<check-id>`.
- **Motion:** none beyond the scroll itself; `prefers-reduced-motion` disables smooth scrolling.
- **Layout:** full-viewport flex column; content max-width `1100px` inside `main`.

### 10. Search field

- **Structure:** a text `<input type="search">` with a visible or visually-hidden label and a mono-friendly placeholder; a magnifier is *not* rendered (no icon font/image).
- **States:** default (`--surface-2` fill, `--border` rule); focus (2px `--accent-focus` outline); populated (clear affordance is the native search clear, kept).
- **Accessibility:** real input (native keyboard/search semantics); label text "Search findings"; `autocomplete="off"` `spellcheck="false"`; case-insensitive substring match across finding text — never regex, never rendered back as HTML.
- **Motion:** none.
- **Layout:** full width above the filter bar.

### 11. Pagination

- **Structure:** native `prev`/`next` buttons, a "Page N of M" indicator, and a native `<select>` for 25/50/100 results per page.
- **States:** prev disabled on first page; next disabled on last page; buttons follow the target-size contract.
- **Accessibility:** `<nav aria-label="Pagination">`; buttons have explicit labels; the page size select has a visible label; page changes preserve focus on the pager.
- **Motion:** none.
- **Layout:** right-aligned below the findings list; hidden entirely when the result count is zero.

### 12. Workload icon (owner-approved exception)

Narrow exception to both the **no image asset / no icon package** ban and the **no vendor logo** ban. Owner-approved for product identification only.

- **Allowlist only:** exactly the 12 checksum-pinned files under `assets/vendor/microsoft-cloud/` from the todo-15 manifest (`manifest.yaml`). Emitted into the offline report bundle as content-hashed `kind: image` assets. CSP remains `img-src 'self'`.
- **Still forbidden:** CDNs, remote fetch, hotlinks, data-URIs, inline vendor SVG, unofficial/legacy/corporate-lockup assets, any image outside the 12-file allowlist, and any use as the LicenseLens product mark.
- **Structure:** local `<img class="workload-icon">` with explicit `width`/`height` (16–20px), `alt=""`, `aria-hidden="true"`, beside visible workload text that remains the accessible name.
- **Placement only:** workload navigation tabs, workload chart/section context, and capability card headers. Never filters, status glyphs, finding-status semantics, product hero, or icon-only controls.
- **No image for `general`.** Missing mapping → text only.
- **States:** decorative; never conveys status or severity.
- **Accessibility:** adjacent visible text names the workload; icons never become accessible names or status indicators.
- **Print:** hide `.workload-icon` (`display: none`) so decorative vendor marks do not waste ink; adjacent text labels remain.
- **Motion:** none.
- **Packaging:** wheel `force-include` and PyInstaller `DATA_DIRS` ship `assets/vendor/microsoft-cloud` → `licenselens/data/vendor/microsoft-cloud`.

## Motion & Interaction

Motion is CSS-only, ≤150ms, limited to `transform`, `opacity`, and non-layout color/border properties.

- `prefers-reduced-motion: reduce` disables all transitions and caret rotation.
- Every interactive element has hover + active + `:focus-visible`.
- Minimum interactive targets follow the target-size contract above.
- No ornamental or ambient motion.

## Depth & Surface

Elevation ladder (cool charcoal):

`--canvas` → `--surface-1` → `--surface-2` → `--surface-3` → `--surface-4`

Every declared surface token MUST be consumed by at least one real selector. Dead surface tokens are a contract violation.

**Shadow reservation (locked):**
- `--shadow-soft`: hero rollup only.
- `--shadow-key`: open disclosures and focused/active panes only.
- Ordinary cards, findings, tiles, filters, tables: **no shadow**.

Edges use 1px rules (`--border` / `--border-strong`). Solid fills only. No gradient, blur, or glow.

## Accessibility Constraints & Accepted Debt

Target is WCAG 2.2 AA, verified against the declared palette.

- **Contrast floors:** body ≥ 4.5:1; large text ≥ 3:1; non-text indicators ≥ 3:1; accent/print floors above.
- **Status is never color-only.** Every status uses label + unique glyph geometry + color.
- **Forced colors.** Glyphs use `currentColor` so they remain distinct under `forced-colors: active`.
- **Print inverts to light ink.** Suppress both shadow tokens. Status-marker backgrounds transparent with contrast-safe status text on white. Links/figures use `--accent-print`. Hero/cards/actions/findings protected from page breaks. Technical disclosure and footer hidden in print.
- **Long tokens wrap safely** with mono stack and `overflow-wrap: anywhere`.
- **Focus is always visible.** 2px `--accent-focus` outline + 2px offset via `:focus-visible`.
- **Reduced motion** is respected everywhere.
- **Null/empty fields** must render without crash (omit or show "Not reported" / "None reported").

**Accepted debt (deliberate, reviewed):**
- (a) **English-only UI.** No i18n.
- (b) **No `general` workload filter.** No current check uses `general`.
- (c) **JSON/Markdown plain labels may differ from HTML PRESENTATION words** when machine semantics require stable `STATUS_PLAIN_LABELS`; document any intentional divergence rather than silently changing JSON enums.
